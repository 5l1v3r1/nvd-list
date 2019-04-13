package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

const (
	repoURL = "https://github.com/knqyf263/nvd-list.git"
)

func push() (err error) {
	exe, err := os.Executable()
	if err != nil {
		return xerrors.Errorf("failed to get binary path: %w", err)
	}

	directory := filepath.Dir(exe)

	// Opens an already existing repository.
	r, err := git.PlainOpen(directory)
	if err != nil {
		return xerrors.Errorf("failed to open git repository: %w", err)
	}

	w, err := r.Worktree()
	if err != nil {
		return xerrors.Errorf("error in git worktree: %w", err)
	}

	// Add a new remote
	// Adds the new file to the staging area.
	log.Println("git remote add")
	_, err = r.CreateRemote(&config.RemoteConfig{
		Name: "http",
		URLs: []string{repoURL},
	})
	if err != nil {
		return xerrors.Errorf("error in git remote add: %w", err)
	}
	defer func() {
		r.DeleteRemote("http")
	}()

	// Adds the new file to the staging area.
	log.Println("git add")
	_, err = w.Add("cves")
	if err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}

	log.Println("git status")
	status, err := w.Status()
	if err != nil {
		return xerrors.Errorf("error in git status: %w", err)
	}
	log.Printf("changed: %d\n", len(status))

	_, err = w.Add("last_updated.txt")
	if err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}

	log.Println("git commit")
	_, err = w.Commit("Automatic update", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Teppei Fukuda",
			Email: "knqyf263@gmail.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return xerrors.Errorf("error in git commit: %w", err)
	}

	log.Println("git push")
	err = r.Push(&git.PushOptions{
		RemoteName: "http",
		Auth: &http.BasicAuth{
			Username: "knqyf263",
			Password: os.Getenv("GITHUB_TOKEN"),
		},
	})
	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			log.Println(err)
			return nil
		}
		return xerrors.Errorf("error in git push: %w", err)
	}

	return nil
}
