package indexer

import (
	"encoding/json"
	"errors"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Mail struct {
	ID       string    `json:"id"`
	Received time.Time `json:"timestamp"`
	Client   string    `json:"client,omitempty"`
	Server   string    `json:"server,omitempty"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Subject  string    `json:"subject"`
	Data     string    `json:"data,omitempty"`
	Status   string    `json:"status,omitempty"`
}

// Sort index by Received date
type ByReceived []Mail

func (a ByReceived) Len() int           { return len(a) }
func (a ByReceived) Less(i, j int) bool { return a[i].Received.After(a[j].Received) }
func (a ByReceived) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// Index folders and watch for new/removed files
func Start(config *configuration.Config) {

	var pathList = []string{
		path.Join(config.DataPath, "inbound"),
		path.Join(config.DataPath, "outbound"),
		path.Join(config.DataPath, "spool"),
	}

	// Refresh existing indexes
	for _, singlePath := range pathList {
		err := refreshIndex(singlePath)
		if err != nil {
			log.Fatalf("Indexer - Failed to refresh index in folder '%s'. Error: %s\n", singlePath, err.Error())
		}
	}

	// Process new/removed files immediately
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		cerr := watcher.Close()
		if err == nil {
			err = cerr
		}
	}()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if strings.HasSuffix(event.Name, ".json") && !strings.Contains(event.Name, "index.json") {
					if event.Op&fsnotify.Create == fsnotify.Create {
						log.Printf("Indexer - New json file '%s'\n", event.Name)

						// For for the end of write operation FIXME: Better way ?
						time.Sleep(500 * time.Millisecond)
						mail, err := LoadMail(event.Name)
						if err == nil {
							err = addToIndex(path.Dir(event.Name), mail)
							if err != nil {
								log.Printf("Indexer - Unable to add mail '%s' to index. Error: %s\n", event.Name, err.Error())
							}
						} else {
							log.Printf("Indexer - Unable to parse mail file '%s'. Error: %s\n", event.Name, err.Error())
						}
					}

					if event.Op&fsnotify.Remove == fsnotify.Remove {
						log.Printf("Indexer - Removed file '%s'\n", event.Name)
						id := path.Base(event.Name)
						id = strings.TrimSuffix(id, ".json")
						err := removeFromIndex(path.Dir(event.Name), id)
						if err != nil {
							log.Printf("Indexer - Unable to remove mail id '%s' from index. Error: %s\n", id, err.Error())
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Indexer - An error occured while watching files. Error: %s\n", err.Error())
			}
		}
	}()

	for _, singlePath := range pathList {
		err = watcher.Add(singlePath)
		if err != nil {
			log.Fatalf("Indexer - Unable to add path '%s' to the watcher. Error: %s\n", singlePath, err.Error())
		}
	}
	<-done
}

// Refresh the whole index
func refreshIndex(folder string) error {
	indexPath := path.Join(folder, "index.json")
	fileList := make([]string, 0)
	mailList := make([]string, 0)
	index, err := LoadIndex(indexPath)
	newIndex := make([]Mail, 0)

	if err != nil {
		log.Printf("Indexer - An error occured while loading index '%s'. Error: %s", indexPath, err.Error())
	}

	if common.FolderExists(folder) {
		err = filepath.Walk(folder, func(filePath string, info os.FileInfo, err error) error {
			if !info.IsDir() && !strings.Contains(filePath, "index.json") {
				id := path.Base(filePath)
				id = strings.TrimSuffix(id, ".json")
				fileList = append(fileList, id)
			}

			return nil
		})

		// remove missing mails
		for _, mail := range index {
			if contains(fileList, mail.ID) {
				newIndex = append(newIndex, mail)
			}
			mailList = append(mailList, mail.ID)
		}

		// add new mails
		for _, id := range fileList {
			if !contains(mailList, id) {
				mailPath := path.Join(folder, id+".json")
				mail, err := LoadMail(mailPath)
				if err == nil {
					mail.Data = ""
					newIndex = append(newIndex, mail)
				} else {
					log.Printf("Indexer - Unable to parse mail file '%s'. Error: %s\n", mailPath, err.Error())
				}
			}
		}

		sort.Sort(ByReceived(newIndex))

		return saveIndex(indexPath, &newIndex)
	} else {
		return errors.New("data folder doesn't exist")
	}
}

// Add a new mail to index
func addToIndex(folder string, mail Mail) error {
	indexPath := path.Join(folder, "index.json")
	index, err := LoadIndex(indexPath)

	if err != nil {
		log.Printf("Indexer - An error occured while loading index '%s'. Error: %s", indexPath, err.Error())
	}

	mail.Data = ""
	index = append(index, mail)

	sort.Sort(ByReceived(index))

	return saveIndex(indexPath, &index)
}

// Remove an item from index
func removeFromIndex(folder string, id string) error {
	indexPath := path.Join(folder, "index.json")
	newIndex := make([]Mail, 0)
	index, err := LoadIndex(indexPath)

	if err != nil {
		log.Printf("Indexer - An error occured while loading index '%s'. Error: %s", indexPath, err.Error())
	}

	for _, mail := range index {
		if mail.ID != id {
			newIndex = append(newIndex, mail)
		}
	}

	return saveIndex(indexPath, &newIndex)
}

// Load an index from a file
func LoadIndex(indexPath string) ([]Mail, error) {
	var index []Mail

	if common.FileExists(indexPath) {

		file, err := ioutil.ReadFile(indexPath)
		if err != nil {
			return index, err
		}

		err = json.Unmarshal(file, &index)
		if err != nil {
			return index, err
		}
	} else {
		index = make([]Mail, 0)
	}

	return index, nil
}

// Save an index to a file
func saveIndex(indexPath string, index *[]Mail) error {
	file, err := json.MarshalIndent(*index, "", " ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(indexPath, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Load a mail from a file
func LoadMail(mailPath string) (Mail, error) {
	var mail Mail

	file, err := ioutil.ReadFile(mailPath)
	if err != nil {
		return mail, err
	}

	err = json.Unmarshal(file, &mail)
	if err != nil {
		return mail, err
	}

	mail.ID = strings.TrimSuffix(path.Base(mailPath), ".json")

	for _, line := range strings.Split(mail.Data, "\n") {
		if strings.HasPrefix(line, "Subject:") {
			mail.Subject = strings.TrimPrefix(line, "Subject: ")
			mail.Subject = strings.TrimSuffix(mail.Subject, "\r")
		}
	}

	return mail, nil
}

// Check if a string is in a slice of strings
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
