FROM python:3.9-slim

# Update package list and install required packages
RUN apt update && apt upgrade -y
RUN apt install socat -y

# Copy challenge files
COPY files /chall/

# Set secure permissions
RUN chown -R root:root /chall && \
    chmod -R 555 /chall

# Make challenge readable by nobody
RUN chmod 644 /chall/challenge.py

# Create run.sh script with 777 permission
RUN echo '#!/bin/bash' > /chall/run.sh && \
    echo 'timeout 30s python3 /chall/challenge.py' >> /chall/run.sh && \
    chmod 755 /chall/run.sh

# Set working directory
WORKDIR /chall

# Expose service on port 9696 using socat - run script via bash
# CMD ["/bin/bash", "-c", "exec socat -d TCP-LISTEN:9696,reuseaddr,fork EXEC:'bash /chall/run.sh',su=nobody"]
CMD ["socat", "TCP-LISTEN:9696,reuseaddr,fork", "EXEC:'sh -c \"/chall/run.sh 2>&1\"',su=nobody"]