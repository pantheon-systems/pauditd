# pauditd

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

## About

pauditd is an alternative to the auditd daemon that ships with many distros.

## Audit Documentation

Kernel Audit System: [audit.c](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) [audit.h](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y)

Good documentation on understanding audit messages:
<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files>

## Usage

### Installation

1. Install [golang](https://golang.org/doc/install), version 1.7 or greater is required

2. Clone the repo

    ```sh
    git clone (this repo)
    cd pauditd
    ```

3. Build the binary

    ```sh
    make
    ```

4. Copy the binary `pauditd` to wherever you'd like

### Testing

- `make test` - run the unit test suite
- `make test-cov-html` - run the unit tests and open up the code coverage results
- `make bench` - run the benchmark test suite
- `make bench-cpu` - run the benchmark test suite with cpu profiling
- `make bench-cpulong` - run the benchmark test suite with cpu profiling and try to get some gc collection

### Running as a service

Check the [contrib](contrib) folder, it contains examples for how to run `pauditd` as a proper service on your machine.

### Example Config

See [pauditd.yaml.example](pauditd.yaml.example)

### Metrics
Metrics have been added and are provided by the statsd client. Statsd is the only supported metrics in pauditd at this time. The available metrics are as follows:

- `pauditd.<hostname>.messages`
  - netlink_dropped
  - total
  - filtered
- `pauditd.<hostname>.http_writer`
  - total_messages
  - dropped_messages
  - http_code
    - 500
    - 404
    - 201
    - Any other code that your service returns
  - latency
  - notif-service-transformer.topic
    - no-topic
    - each topics that the messages are sent to

## HttpWriter Output Plugin

The http writer output plugin allows you to send audit messages to an http service of your choice. It allows for configuration of circuit breaking, ssl, and the body that is sent to the service in the request. The ResponseBodyTransformer interface is the extension point for specifying how the http request body will be formatted.

### Noop Transformer

Default transformer used when none is specified, does not touch the []byte message body and ships the pauditd message as the body.

### NotificationServiceTransformer

This transforms the body into a structure for a pub/sub proxy called notification service. It looks at the messages rule key set with the `-k <rule key> option when creating the audit rule. It uses that as the topic in pub/sub to send the message. The DTO/Service Contract for the notification service (pubsub proxy) is:

```go
type notification struct {
    Topic      string            `json:"topic"`
    Attributes map[string]string `json:"attributes"`
    Data       json.RawMessage   `json:"data"`
    Version    string            `json:"version"`
}
```

The service expects this as a POST and as json. The data field is the []byte message value from pauditd. This could be used to send to any message bus as the proxy allows for a single service contract without care for the end destination.

#### Adding a tranformer for the http writer

To send messages to a web service that requires a DTO/Service Contract that does not match the structure of the messages as they come from pauditd you will need to implement a `ResponseBodyTransformer`. This interface contains a single function to Transform the body of the http request to the service into the structure required. It is passed a []byte which are the bytes from pauditd representing the message and a uuid which is the trace id for the message and request going out to the service.

This is stored as a singleton and should be thread/go-routine safe in the way that it stores its state if it requires state to operate.

```go
// ResponseBodyTransformer is an interface that allows different
// preparations to happen on the body of the message before
// it is sent (STORED AS A SINGLETON)
type ResponseBodyTransformer interface {
    // Transform takes the result in byte array and returns
    // a transformed byte array or error
    Transform(uuid.UUID, []byte) ([]byte, error)
}
```

## FAQ

### I am seeing `Error during message receive: no buffer space available` in the logs

This is because `pauditd` is not receiving data as quickly as your system is generating it. You can increase
the receive buffer system wide and maybe it will help. Best to try and reduce the amount of data `pauditd` has
to handle.

If reducing audit velocity is not an option you can try increasing `socket_buffer.receive` in your config.
See [Example Config](#example-config) for more information

```yaml
socket_buffer:
    receive: <some number bigger than (the current value * 2)>
```

### Sometime files don't have a `name`, only `inode`, what gives?

The kernel doesn't always know the filename for file access. Figuring out the filename from an inode is expensive and
error prone.

You can map back to a filename, possibly not *the* filename, that triggured the audit line though.

```sh
sudo debugfs -R "ncheck <inode to map>" /dev/<your block device here>
```

### I don't like math and want you to tell me the syslog priority to use

Use the default, or consult this handy table.

Wikipedia has a pretty good [page](https://en.wikipedia.org/wiki/Syslog) on this

|                   | emerg (0)| alert (1) | crit (2)  | err (3) | warn (4) | notice (5) | info (6)  | debug (7) |
|-------------------|----------|-----------|-----------|---------|----------|------------|-----------|-----------|
| **kernel (0)**    | 0        | 1         | 2         | 3       | 4        | 5          | 6         | 7         |
| **user (1)**      | 8        | 9         | 10        | 11      | 12       | 13         | 14        | 15        |
| **mail (2)**      | 16       | 17        | 18        | 19      | 20       | 21         | 22        | 23        |
| **daemon (3)**    | 24       | 25        | 26        | 27      | 28       | 29         | 30        | 31        |
| **auth (4)**      | 32       | 33        | 34        | 35      | 36       | 37         | 38        | 39        |
| **syslog (5)**    | 40       | 41        | 42        | 43      | 44       | 45         | 46        | 47        |
| **lpr (6)**       | 48       | 49        | 50        | 51      | 52       | 53         | 54        | 55        |
| **news (7)**      | 56       | 57        | 58        | 59      | 60       | 61         | 62        | 63        |
| **uucp (8)**      | 64       | 65        | 66        | 67      | 68       | 69         | 70        | 71        |
| **clock (9)**     | 72       | 73        | 74        | 75      | 76       | 77         | 78        | 79        |
| **authpriv (10)** | 80       | 81        | 82        | 83      | 84       | 85         | 86        | 87        |
| **ftp (11)**      | 88       | 89        | 90        | 91      | 92       | 93         | 94        | 95        |
| **ntp (12)**      | 96       | 97        | 98        | 99      | 100      | 101        | 102       | 103       |
| **logaudit (13)** | 104      | 105       | 106       | 107     | 108      | 109        | 110       | 111       |
| **logalert (14)** | 112      | 113       | 114       | 115     | 116      | 117        | 118       | 119       |
| **cron (15)**     | 120      | 121       | 122       | 123     | 124      | 125        | 126       | 127       |
| **local0 (16)**   | 128      | 129       | 130       | 131     | 132      | 133        | 134       | 135       |
| **local1 (17)**   | 136      | 137       | 138       | 139     | 140      | 141        | 142       | 143       |
| **local2 (18)**   | 144      | 145       | 146       | 147     | 148      | 149        | 150       | 151       |
| **local3 (19)**   | 152      | 153       | 154       | 155     | 156      | 157        | 158       | 159       |
| **local4 (20)**   | 160      | 161       | 162       | 163     | 164      | 165        | 166       | 167       |
| **local5 (21)**   | 168      | 169       | 170       | 171     | 172      | 173        | 174       | 175       |
| **local6 (22)**   | 176      | 177       | 178       | 179     | 180      | 181        | 182       | 183       |
| **local7 (23)**   | 184      | 185       | 186       | 187     | 188      | 189        | 190       | 191       |

### I am seeing duplicate entries in syslog

This is likely because you are running `journald` which is also reading audit events. To disable it you need to disable the functionality in `journald`.

```sh
sudo systemctl mask systemd-journald-audit.socket
```

## Thanks

To slackhq for the inspiration via https://github.com/slackhq/go-audit
