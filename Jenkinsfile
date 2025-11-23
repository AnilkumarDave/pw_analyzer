pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Test Dependencies') {
            steps {
                sh 'pip install -r requirements-tests.txt'
            }
        }

        stage('Run Tests') {
            steps {
                sh 'pytest --alluredir=allure-results'
            }
        }
    }

    post {
        always {
            junit 'allure-results/*.xml'
        }
    }
}
