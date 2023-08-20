package simploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	gssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-github/v39/github"
	"github.com/gorilla/mux"
	"github.com/melbahja/goph"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type RawConfig struct {
	WebhookSecret    string `json:"webhook-secret"`
	SSHKey           string `json:"ssh-key"`
	SSHKeyPassphrase string `json:"ssh-key-passphrase"`
	InfoWebhook      string `json:"info-webhook"`
}

type SSHConfig struct {
	Host      string `json:"host"`
	Port      uint   `json:"port"`
	Username  string `json:"username"`
	Directory string `json:"directory"`
}

type RepoConfig struct {
	URL      string    `json:"url"`
	Branches []string  `json:"branches"`
	Scripts  []string  `json:"scripts"`
	SSH      SSHConfig `json:"ssh"`
}

func (c RepoConfig) HasBranch(r string) bool {
	for _, ref := range c.Branches {
		if r == ref {
			return true
		}
	}
	return false
}

type SimployServer struct {
	hooksecret []byte
	repos      []RepoConfig
	sshAuth    goph.Auth
	gitAuth    *gssh.PublicKeys
	hkcb       ssh.HostKeyCallback
	infoHook   string
}

func Run(config RawConfig, repos []RepoConfig) {
	s := SimployServer{
		repos: repos,
		hkcb: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// None!
			return nil
		},
		infoHook: config.InfoWebhook,
	}

	// SSH key
	key, err := goph.Key(config.SSHKey, config.SSHKeyPassphrase)
	if err != nil {
		logrus.Fatal(err)
	}
	s.sshAuth = key

	// Git key
	gitkey, err := gssh.NewPublicKeysFromFile("git", config.SSHKey, config.SSHKeyPassphrase)
	if err != nil {
		logrus.Fatal(err)
	}
	gitkey.HostKeyCallback = s.hkcb
	s.gitAuth = gitkey

	// Router
	r := mux.NewRouter()
	r.HandleFunc("/webhook", s.WebHook).Methods("POST")

	addr := "127.0.0.1:8180"
	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	logrus.Printf("Starting HTTP Server listening at %q", "http://"+addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logrus.Printf("%v", err)
	} else {
		logrus.Println("Goodbye!")
	}
}

type infohook struct {
	Content string `json:"content"`
}

func (s *SimployServer) postInfo(msg string) {
	h := infohook{
		Content: msg,
	}
	if len(h.Content) > 2000 { // Discord webhook limit
		h.Content = h.Content[len(h.Content)-1997:len(h.Content)] + "..."
	}
	bin, err := json.Marshal(h)
	if err != nil {
		logrus.Error(errors.Wrap(err, "error marshalling JSON for webhook"))
		return
	}
	_, err = http.Post(s.infoHook, "application/json", bytes.NewBuffer(bin))
	if err != nil {
		logrus.Error(errors.Wrap(err, "error posting to info webhook"))
	}
}

func (s *SimployServer) handlePush(event github.PushEvent) error {
	repo := event.GetRepo()

	// Find repo
	var simployRepo RepoConfig
	for _, r := range s.repos {
		if r.URL == repo.GetSSHURL() {
			simployRepo = r
			break
		}
	}
	if simployRepo.URL == "" {
		// No repo with matching SSH URL
		return errors.Errorf("no matching repo found for %s", repo.GetSSHURL())
	}

	branch := strings.TrimPrefix(event.GetRef(), "refs/heads/")

	if !simployRepo.HasBranch(branch) {
		// Ref of push doesn't match any allowed ref. Not an error, but don't proceed
		logrus.Warnf("pushed branch %s for repo %s not in %v", event.GetRef(), simployRepo.URL, simployRepo.Branches)
		return nil
	}

	pusher := event.GetPusher()
	var pusherText string
	if pusher != nil {
		pusherText = " (" + *pusher.Login + ")"
	}

	go func() {
		s.postInfo("started deploying " + repo.GetFullName() + "@" + branch + pusherText)

		cloned, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
			URL:               simployRepo.URL,
			ReferenceName:     plumbing.NewBranchReferenceName(branch),
			SingleBranch:      true,
			Depth:             100, // Should be OK
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			Auth:              s.gitAuth,
		})
		if err != nil {
			logrus.Error(errors.Wrapf(err, "failed cloning %s", simployRepo.URL))
			return
		}
		logrus.Debugf("cloned repo %s", simployRepo.URL)

		// Create simploy remote
		remote, err := cloned.CreateRemote(&config.RemoteConfig{
			Name: "simploy",
			URLs: []string{fmt.Sprintf(
				"ssh://%s@%s:%d%s", // ssh://user@host:1234/srv/git/example
				simployRepo.SSH.Username,
				simployRepo.SSH.Host,
				simployRepo.SSH.Port,
				simployRepo.SSH.Directory,
			)},
		})
		if err != nil {
			logrus.Error(err)
			return
		}

		// Push to remote!
		pushAuth := &gssh.PublicKeys{
			User:   simployRepo.SSH.Username,
			Signer: s.gitAuth.Signer,
		}
		pushAuth.HostKeyCallback = s.hkcb
		err = cloned.Push(&git.PushOptions{
			RemoteName: "simploy",
			Auth:       pushAuth,
			Force:      true,
			RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/" + branch + ":refs/heads/simploy")},
		})
		if err != nil {
			if err == git.NoErrAlreadyUpToDate {
				logrus.Warn("remote already up-to-date")
				return
			}
			logrus.Error(errors.Wrapf(err, "failed pushing %s to %s", simployRepo.URL, remote.Config().URLs[0]))
			return
		}
		logrus.Debugf("pushed repo to %s", remote.Config().URLs[0])

		// Connect with SSH
		client, err := goph.NewConn(&goph.Config{
			Auth:    s.sshAuth,
			User:    simployRepo.SSH.Username,
			Addr:    simployRepo.SSH.Host,
			Port:    simployRepo.SSH.Port,
			Timeout: time.Second * 20,
			Callback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				// None!
				return nil
			},
		})
		if err != nil {
			logrus.Error(err)
			return
		}
		defer client.Close()
		logrus.Debugf("opened connection for %s to %s", client.User(), client.RemoteAddr().String())

		// Merge simploy to current branch
		output, err := client.Run(fmt.Sprintf("cd %s && git merge simploy", simployRepo.SSH.Directory))
		if err != nil {
			logrus.Error(errors.Wrapf(err, "merge failed: %s", output))
			return
		}
		logrus.Debug("merge: " + string(output))

		// Execute scripts
		for _, script := range simployRepo.Scripts {
			bin, err := ioutil.ReadFile(filepath.Join("./scripts", script))
			if err != nil {
				logrus.Error(err)
				return
			}
			logrus.Debug("executing " + script)

			ctx, cnc := context.WithTimeout(context.Background(), time.Minute*10)
			defer cnc()
			output, err := client.RunContext(
				ctx,
				fmt.Sprintf("cd %s && %s", simployRepo.SSH.Directory, string(bin)),
			)
			logrus.Debug("output: " + string(output))
			if err != nil {
				content := stripansi.Strip(string(output))
				if (len(content) + 42) > 2000 { // Discord webhook limit
					content = "..." + content[len(content)-1997:]
				}
				s.postInfo("bad result from deployment script:\n```" + content + "```")
				logrus.Error(err)
				return
			}
		}

		s.postInfo("finished deploying " + repo.GetFullName() + "@" + branch + pusherText)
	}()

	return nil
}

func (s *SimployServer) WebHook(w http.ResponseWriter, r *http.Request) {
	payload, err := github.ValidatePayload(r, s.hooksecret)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	deliveryID := github.DeliveryID(r)
	logrus.Infof("Received webhook with delivery ID %s", deliveryID)

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch ev := event.(type) {
	case *github.PushEvent:
		if ev.Pusher == nil || ev.HeadCommit == nil || ev.Repo == nil {
			logrus.Error("missing required portion(s) of payload")
			w.WriteHeader(http.StatusBadRequest)
		}
		logrus.Infof(
			"received push for repo %s to %s (%s) by %s <%s>",
			ev.Repo.GetSSHURL(), ev.HeadCommit.GetID(), ev.HeadCommit.GetMessage(),
			ev.Pusher.GetLogin(), ev.Pusher.GetEmail(),
		)
		err = s.handlePush(*ev)
		if err != nil {
			err = errors.Wrap(err, "error handling push delivery "+deliveryID)
			logrus.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
	default:
		logrus.Errorf("unimplemented event type %s", github.WebHookType(r))
		w.WriteHeader(http.StatusNotImplemented)
	}
	w.WriteHeader(http.StatusOK)
}
