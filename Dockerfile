FROM debian:bullseye-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    aircrack-ng \
    python3 \
    python3-pip \
    wireless-tools \
    iw \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install pandas

# Create working directory
WORKDIR /pentest

# Copy script and requirements
COPY pen_test.py .
COPY 8digit.lst .

# Create capture directory
RUN mkdir -p captures

# Set script as executable
RUN chmod +x pen_test.py

ENTRYPOINT ["python3", "pen_test.py"] 