FROM ubuntu:18.04

# Update package list and install required packages
RUN apt update && apt upgrade -y && apt update --fix-missing
RUN apt install socat -y

# Install 32-bit support libraries (for running 32-bit binaries)
RUN dpkg --add-architecture i386
RUN apt update
RUN apt install libc6:i386 libncurses5:i386 libstdc++6:i386 -y

# Copy challenge files
COPY files /chall/

# Set secure permissions
RUN chmod 700 /usr/bin/* /bin/* /tmp /dev/shm
RUN chmod 755 /usr/bin/env /bin/dash /bin/bash /bin/sh /bin/cat /usr/bin/groups /usr/bin/id /bin/ls
RUN chown root:root -R /chall

# Make binary executable
RUN chmod +x /chall/cek-var

# Set working directory
WORKDIR /chall

# Expose service on port 9999 using socat
CMD ["/bin/bash", "-c", "exec socat -d TCP-LISTEN:9999,reuseaddr,fork EXEC:./cek-var,su=nobody"]
