FROM adoptopenjdk:17-jre-hotspot

LABEL org.opencontainers.image.url=https://github.com/SonarSource/docker-sonarqube

ENV LANG='en_US.UTF-8' \
    LANGUAGE='en_US:en' \
    LC_ALL='en_US.UTF-8'

#
# SonarQube setup
#
ARG SONARQUBE_VERSION=10.0.0.68432
ARG SONARQUBE_ZIP_URL=https://binaries.sonarsource.com/CommercialDistribution/sonarqube-developer/sonarqube-developer-${SONARQUBE_VERSION}.zip
ENV SONARQUBE_HOME=C:/opt/sonarqube \
    SONAR_VERSION="${SONARQUBE_VERSION}" \
    SQ_DATA_DIR="C:/opt/sonarqube/data" \
    SQ_EXTENSIONS_DIR="C:/opt/sonarqube/extensions" \
    SQ_LOGS_DIR="C:/opt/sonarqube/logs" \
    SQ_TEMP_DIR="C:/opt/sonarqube/temp"

RUN set -eux; \
    New-Item -ItemType Directory -Path C:\opt; \
    cd C:\opt; \
    Invoke-WebRequest -Uri "${SONARQUBE_ZIP_URL}" -OutFile sonarqube.zip; \
    Expand-Archive -Path sonarqube.zip -DestinationPath .; \
    Move-Item -Path "sonarqube-${SONARQUBE_VERSION}" -Destination sonarqube; \
    Remove-Item -Path sonarqube.zip;

COPY entrypoint.sh ${SONARQUBE_HOME}/docker/

WORKDIR ${SONARQUBE_HOME}
EXPOSE 9000

CMD [ "sh", "-c", "${SONARQUBE_HOME}/docker/entrypoint" ]
