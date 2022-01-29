package work

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var sessX = regexp.MustCompile(`pid\s\d+`)

const SimployKeyDataEnv = "SIMPLOY_SSH_KEY_DATA"
const SimployKeyPassEnv = "SIMPLOY_SSH_KEY_PASS"

func ExecuteScripts(sess *ssh.Session, giturl string, scripts []string, key, pass string) error {
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	err := sess.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return err
	}

	// Setup pipes
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	// Start shell
	err = sess.Shell()
	if err != nil {
		return err
	}

	// Command execution function
	exec := func(cmd string) error {
		_, err := fmt.Fprintf(stdin, "%s\n", cmd)
		if err != nil {
			return errors.Wrapf(err, "failed writing command %s to stdin", cmd)
		}
		return nil
	}

	// Setup SSH key env
	exec("unset HISTFILE") // Stop logging to prevent sensitive info leakage
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed unsetting HISTFILE")
	}
	exec("export " + SimployKeyDataEnv + "=" + strings.ReplaceAll(strings.ReplaceAll(key, "\n", "\\n"), "\r", ""))
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed exporting key data")
	}
	exec("export " + SimployKeyPassEnv + "=" + pass)
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed exporting key pass")
	}
	exec("echo HELLO")

	// Start new SSH agent
	err = exec("eval $(ssh-agent -s)")
	if err != nil {
		return errors.Wrap(err, "failed starting ssh-agent")
	}
	sob := stdout.Bytes()
	match := sessX.Find(sob)
	if len(match) == 0 {
		logrus.Debug("stdout: " + string(sob))
		logrus.Debug("stderr: " + stderr.String())
		return errors.New("failed getting ssh-agent pid from output")
	}
	agentPID := string(match[4:])
	logrus.Debug("started ssh-agent with pid " + agentPID)

	// Add key to agent
	rhp, err := generateRandomString(8)
	if err != nil {
		return err
	}
	filePrefix := "/tmp/simploy-" + rhp
	err = exec(fmt.Sprintf(
		`echo -e "$%s" > %s-key.openssh && echo -e '#!/bin/sh\nexec cat' > %s-helper.sh && chmod +x %s-helper.sh`,
		SimployKeyDataEnv, filePrefix, filePrefix, filePrefix,
	))
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed making helper and key file")
	}
	err = exec(fmt.Sprintf(
		`echo "$%s"| SSH_ASKPASS=%s-helper.sh ssh-add -t 3600 %s-key.openssh`,
		SimployKeyPassEnv, filePrefix, filePrefix,
	))
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed adding key to ssh agent")
	}

	for _, script := range scripts {
		stdout.Reset()
		stderr.Reset()

		f, err := os.Open(script)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		logrus.Debug("Executing: " + script)
		err = exec(string(data))
		logrus.Debug("stdout: " + strings.TrimSpace(stdout.String()))
		logrus.Debug("stderr: " + strings.TrimSpace(stderr.String()))
		if err != nil {
			return err
		}
	}

	// Kill ssh-agent
	err = exec("kill " + agentPID)
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed killing ssh-agent")
	}

	// File cleanup
	exec("rm -f " + filePrefix + "*")
	if err != nil {
		logrus.Debug("stderr: " + stderr.String())
		return errors.Wrap(err, "failed removing helper and key file")
	}

	// Exit session
	exec("exit")
	err = sess.Wait()
	if err != nil {
		return err
	}

	return nil
}
