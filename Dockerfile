FROM alpine:3.21

RUN apk add audit

ADD pauditd /opt/pauditd/pauditd

CMD /opt/pauditd/pauditd -config /config/pauditd.yaml