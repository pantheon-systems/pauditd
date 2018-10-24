FROM alpine:3.8

ADD pauditd /pauditd

RUN apk add audit


CMD /pauditd -config /config/pauditd.yaml
