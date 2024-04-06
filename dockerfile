FROM golang:latest

LABEL maintainer="Michael Coleman"

ENV CGO_ENABLED=1

ENV GIN_MODE=release

# Configure Go
ENV GOUSER gouser
#ENV GOROOT /usr/lib/go
#ENV GOPATH /go
#ENV PATH /go/bin:$PATH

# Create a group and user
RUN useradd -s /bin/bash -m ${GOUSER} -g users

WORKDIR /${GOUSER}

COPY go.mod /${GOUSER}
COPY *.go /${GOUSER}
COPY go.sum /${GOUSER}
COPY /templates /${GOUSER}/templates

# Adjust permissions for the copied files and directories
RUN chown -R ${GOUSER}:users /${GOUSER} && \
    chmod -R 755 /${GOUSER}

RUN go mod download && \
    chown -R ${GOUSER}:users /go

RUN go install -v golang.org/x/tools/gopls@latest && \
    go install -v golang.org/x/tools/cmd/goimports@latest && \
    go get blindfold-api

RUN apt update && apt install gzip && \
    curl -LO "https://vesio.azureedge.net/releases/vesctl/$(curl -s https://downloads.volterra.io/releases/vesctl/latest.txt)/vesctl.linux-amd64.gz" && \
    gzip -d vesctl.linux-amd64.gz && mv vesctl.linux-amd64 vesctl && chmod +x vesctl

USER ${GOUSER}

ENV PATH="${PATH}:/${GOUSER}}"

#RUN go get blindfold-api

EXPOSE 8080

#CMD [ "entrypoint.sh" ]
CMD ["bash"]