FROM alpine:3.20

RUN apk add --no-cache \
    asterisk \
    asterisk-sounds-en \
    && rm -rf /var/cache/apk/*

# Remove default configs we'll override
RUN rm -f /etc/asterisk/pjsip.conf /etc/asterisk/extensions.conf

COPY conf/pjsip.conf /etc/asterisk/pjsip.conf
COPY conf/extensions.conf /etc/asterisk/extensions.conf
COPY conf/logger.conf /etc/asterisk/logger.conf
COPY conf/rtp.conf /etc/asterisk/rtp.conf

# Ensure res_pjsip modules are loaded
RUN echo "[modules]" > /etc/asterisk/modules.conf && \
    echo "autoload=yes" >> /etc/asterisk/modules.conf && \
    echo "noload=chan_sip.so" >> /etc/asterisk/modules.conf

EXPOSE 5060/udp 5060/tcp 10000-10100/udp

CMD ["asterisk", "-fvvv"]
