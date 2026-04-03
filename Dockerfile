FROM zaproxy/zap-stable:2.17.0

WORKDIR /zap

RUN mkdir -p /zap/src/logs

COPY . ./src


# CMD [ "zap.sh", "-cmd", "-autorun", "src/zap-automationtest.yaml"]

CMD [ "python3","src/zap_log_parse.py"]