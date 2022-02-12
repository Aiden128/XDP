# XDP

## Setup

1. Install arping and the required packgage above
2. Insert the code below into .bashrc

```bash
# Example: nsenter-ctn <ctn-id> -n ip addr show eth0
# nsenter is tool for commanding in namespace
function nsenter-ctn () {
    CTN=$1 # Container ID or name
    PID=$(sudo docker inspect --format "{{.State.Pid}}" $CTN)
    shift 1 # Remove the first arguement, shift remaining ones to the left
    sudo nsenter -t $PID $@
}
```
3. source ~/.bashrc


## Compile
clang -O2 -Wall -target bpf -c {name}.c -o {name}.o

## Enviorment

- Ubuntu: 20.04
- Docker: 19.03.13
- Clang: 10.0.0-4ubuntu1
- tc (iproute2): tc utility, iproute2-ss200127

