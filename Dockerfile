FROM us-docker.pkg.dev/pantheon-artifacts/internal/alpine:3.22

RUN apk add audit

ADD pauditd /opt/pauditd/pauditd

CMD /opt/pauditd/pauditd -config /config/pauditd.yaml