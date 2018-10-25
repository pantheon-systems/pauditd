FROM alpine:3.8

RUN apk add audit

ADD pauditd /opt/pauditd/pauditd

CMD /opt/pauditd/pauditd -config /config/pauditd.yaml