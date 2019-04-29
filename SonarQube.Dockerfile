FROM sonarqube:6.7.5

# Remove bundled plugins
RUN ls -la $SONARQUBE_HOME/lib/bundled-plugins && \
    rm -rf $SONARQUBE_HOME/lib/bundled-plugins/sonar-java-plugin-*.jar

# Install plugins
ENV SONAR_JAVA_PLUGIN_VERSION 5.9.2.16552
RUN curl --fail --silent --show-error --location --output $SONARQUBE_HOME/extensions/plugins/sonar-java-plugin-${SONAR_JAVA_PLUGIN_VERSION}.jar \
    https://binaries.sonarsource.com/Distribution/sonar-java-plugin/sonar-java-plugin-${SONAR_JAVA_PLUGIN_VERSION}.jar

ENV SONAR_JAVASCRIPT_PLUGIN_VERSION 5.1.1.7506
RUN cd $SONARQUBE_HOME/extensions/plugins && \
    curl --fail --silent --show-error --location --output sonar-javascript-plugin-${SONAR_JAVASCRIPT_PLUGIN_VERSION}.jar \
    https://binaries.sonarsource.com/Distribution/sonar-javascript-plugin/sonar-javascript-plugin-${SONAR_JAVASCRIPT_PLUGIN_VERSION}.jar

ENV SONAR_PYTHON_PLUGIN_VERSION 1.9.1.2080
RUN cd $SONARQUBE_HOME/extensions/plugins && \
    curl --fail --silent --show-error --location --output sonar-python-plugin-${SONAR_PYTHON_PLUGIN_VERSION}.jar \
    https://binaries.sonarsource.com/Distribution/sonar-python-plugin/sonar-python-plugin-${SONAR_PYTHON_PLUGIN_VERSION}.jar

# Third-party plugins
ENV SONAR_FINDBUGS_PLUGIN_VERSION 3.9.3
RUN cd $SONARQUBE_HOME/extensions/plugins && \
    curl --fail --silent --show-error --location --output sonar-findbugs-plugin-${SONAR_FINDBUGS_PLUGIN_VERSION}.jar \
    https://github.com/SonarQubeCommunity/sonar-findbugs/releases/download/${SONAR_FINDBUGS_PLUGIN_VERSION}/sonar-findbugs-plugin-${SONAR_FINDBUGS_PLUGIN_VERSION}.jar

# Skyscanner plugins
ENV SONAR_JAVA_SECRETS_PLUGIN_VERSION 1.3.0
RUN cd $SONARQUBE_HOME/extensions/plugins && \
    curl --fail --silent --show-error --location --output sonar-secrets-java-${SONAR_JAVA_SECRETS_PLUGIN_VERSION}.jar \
    https://github.com/Skyscanner/sonar-secrets/releases/download/v${SONAR_JAVA_SECRETS_PLUGIN_VERSION}/sonar-secrets-java-${SONAR_JAVA_SECRETS_PLUGIN_VERSION}.jar

ENV SONAR_JS_SECRETS_PLUGIN_VERSION 1.3.0
RUN cd $SONARQUBE_HOME/extensions/plugins && \
    curl --fail --silent --show-error --location --output sonar-secrets-javascript-${SONAR_JS_SECRETS_PLUGIN_VERSION}.jar \
    https://github.com/Skyscanner/sonar-secrets/releases/download/v${SONAR_JS_SECRETS_PLUGIN_VERSION}/sonar-secrets-javascript-${SONAR_JS_SECRETS_PLUGIN_VERSION}.jar

ENTRYPOINT ${SONARQUBE_HOME}/bin/run.sh
