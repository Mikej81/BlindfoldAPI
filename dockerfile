FROM golang:latest

LABEL maintainer="Michael Coleman"

ENV CGO_ENABLED=1

ENV GIN_MODE=release

# Configure Go
ENV GOUSER gouser

# Create a group and user
RUN useradd -s /bin/bash -m ${GOUSER} -g users

WORKDIR /${GOUSER}

COPY /templates /${GOUSER}/templates
COPY ./entrypoint.sh /${GOUSER}/entrypoint.sh
COPY ./blindfold-server /${GOUSER}/blindfold-server

RUN chown -R ${GOUSER} ./entrypoint.sh && \
    chmod +x /${GOUSER}/entrypoint.sh

RUN apt update && apt install gzip && \
    curl -LO "https://vesio.azureedge.net/releases/vesctl/$(curl -s https://downloads.volterra.io/releases/vesctl/latest.txt)/vesctl.linux-amd64.gz" && \
    gzip -d vesctl.linux-amd64.gz && mv vesctl.linux-amd64 vesctl && chmod +x vesctl

USER ${GOUSER}

EXPOSE 8080

ENTRYPOINT [ "./entrypoint.sh" ]
#CMD ["bash"]