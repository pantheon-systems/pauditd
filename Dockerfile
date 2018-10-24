FROM alpine:3.8

ADD pauditd /pauditd

CMD /pauditd -config /config/pauditd.yaml
