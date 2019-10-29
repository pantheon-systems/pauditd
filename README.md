# pauditd

[![CircleCI](https://circleci.com/gh/pantheon-systems/pauditd/tree/master.svg?style=svg)](https://circleci.com/gh/pantheon-systems/pauditd/tree/master)

## About

pauditd is an alternative to the auditd daemon that ships with many distros.

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

## Audit Documentation

Kernel Audit System: [audit.c](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) [audit.h](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y)

Good documentation on understanding audit messages:
<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files>

## Usage

### Installation

1. Install [golang](https://golang.org/doc/install), version 1.10 or greater is required

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

#### Dependencies

This binary must be run priviledged and expects to run as root with access to the PID namespace of the host if running in a container. In addition, audit linux package must be installed as this software uses the `auditctl` binary to manipulate the audit rules.

#### Systemd Unit

pauditd can run inside a systemd container/unit running on most types of linux. The systemd service unit file can be found at [examples](examples)

#### Docker

The `pauditd` binary can be run in inside a docker container running on the server. The docker image is built with merge to master and can be found at: [quay.io/getpantheon/pauditd](https://quay.io/repository/getpantheon/pauditd)

To run with the docker command:

```console
    docker run -v <pathtoconfigfile>:/config --privileged --pid="host" quay.io/getpantheon/pauditd:latest
```

If you are monitoring the host file system with file system watch rules then you will have to mount the host directory that you are monitoring into the container with an additional `-v <path-to-monitored>:<path-to-monitored>` to allow access to that filesystem.

### Example Config

See [./examples/pauditd.yaml.example](./examples/pauditd.yaml.example)

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

This transforms the body into a structure for a pub/sub proxy called notification service. It looks at the messages rule key set with the `-k <rule key>` option when creating the audit rule. It uses that as the topic in pub/sub to send the message. The DTO/Service Contract for the notification service (pubsub proxy) is:

```go
type notification struct {
    Topic      string            `json:"topic"`
    Attributes map[string]string `json:"attributes"`
    Data       json.RawMessage   `json:"data"`
    Version    string            `json:"version"`
}
```

The service expects this as a POST and as json. The data field is the []byte message value from pauditd. This could be used to send to any message bus as the proxy allows for a single service contract without care for the end destination.

This can be configured to attach additional data into the attributes map[string]string. These extra attributes are set in the configuration file under output.notification_service_transformer top level configuration.

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

### Dropped Messages by the Kernel

If you are seeing `Error during message receive: no buffer space available` in the logs or seeing dropped messages
in the metrics. This is because `pauditd` is not receiving data as quickly as your system is generating it. You can increase
the receive buffer system wide and maybe it will help. You can also increase your `rmem-max` kernel tunable to allow netlink
socket buffers to be larger. This will not increase the other netlink sockets (TCP) just the ones that the operator configures
to utilize the new buffer room.

After increasing the `rmem-max` increase the `socket_buffer.receive` in your config.
See [Example Config](#example-config) for more information

```yaml
socket_buffer:
    receive: <some number bigger than (the current value * 2)>
```

### Sometime files don't have a `name`, only `inode`?

The kernel doesn't always know the filename for file access. Figuring out the filename from an inode is expensive and error prone.

You can map back to a filename, possibly not *the* filename, that triggured the audit line though.

```console
sudo debugfs -R "ncheck <inode to map>" /dev/<your block device here>
```

### Syslog Output Priority

Wikipedia has a pretty good [page](https://en.wikipedia.org/wiki/Syslog) on this

### Syslog/Journal Has Audit Logs

This is likely because you are running `journald` which is also reading audit events. To disable it you need to disable the functionality in `journald`.

```console
sudo systemctl mask systemd-journald-audit.socket
```

You may have to restart the _systemd-journald.service_ after masking the socket.

if this problem persists it is because the netlink socket buffers are getting full and the default for overflow is to dump to the kernel logging sub-system. This can be disabled by setting the audit configuration option for what to do when the enqueue on the buffer fails. You can set this setting by using a special audit rule in the `pauditd.yaml` configuration file:

```
-f N
```

Where the `N` is either 0, 1 or 2.

```
0 -> discard
1 -> kernel logging subsystem
2 -> panic
```

## Thanks

To slackhq for the inspiration via https://github.com/slackhq/go-audit
