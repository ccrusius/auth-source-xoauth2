all: oauth

oauth: oauth.go go.sum
	go build

go.sum: go.mod
	go get

clean:
	$(RM) oauth go.sum
