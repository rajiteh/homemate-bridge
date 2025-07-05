ARG BUILD_FROM
FROM $BUILD_FROM as builder

# Install build dependencies
RUN apk add --no-cache python3 py3-pip py3-virtualenv gcc musl-dev libffi-dev openssl-dev git

# Create virtual environment and install homemate-bridge
RUN python3 -m venv /opt/venv \
    && . /opt/venv/bin/activate \
    && pip install --upgrade pip \
    && git clone https://github.com/rajiteh/homemate-bridge.git \
    && cd homemate-bridge \
    && git checkout 9384a06f8bfbfc4586933ac750ca30276a5962c0 \
    && pip install . \
    && pip install -r requirements.txt \
    && rm -rf .git

FROM $BUILD_FROM

# Install only runtime dependencies
RUN apk add --no-cache python3 py3-pip

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy your scripts/configs
COPY run.sh /
RUN chmod a+x /run.sh

ENV PATH="/opt/venv/bin:$PATH"

CMD [ "/run.sh" ]