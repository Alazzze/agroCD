[![GitHub Actions Status](https://github.com/Alazzze/docker-compose-test/workflows/docker-compose/badge.svg)](https://github.com/Alazzze/docker-compose-test/actions)

# Docker Compose Test Project

## Overview

This project is an example of using Docker Compose to run MySQL, PHPMyAdmin, and WordPress in a convenient and isolated environment. The project also utilizes GitHub Actions for automated testing and updates.

## Contents

1. [Project Structure](#project-structure)
2. [Getting Started](#getting-started)
3. [GitHub Actions](#github-actions)

## Project Structure

- **docker-compose.yml**: Configuration file for Docker Compose.
- **.env.example**: Example environment variables file.
- **.github/workflows**: Directory for GitHub Actions configuration.

## Getting Started!!!

1. Clone this repository:

   ```bash
   git clone https://github.com/Alazzze/docker-compose-test
   cd docker-compose-test
   ```

2. Create the `.env` file based on `.env.example` and set the environment variable values.

3. Run the projects using Docker Compose:

   ```bash
   docker-compose up -d
   ```

4. Wait for all containers to start, then check the status:

   ```bash
   docker-compose ps
   ```

5. Test the connection to MySQL:

   ```bash
   MYSQL_ROOT_PASSWORD=$(grep MYSQL_ROOT_PASSWORD .env | cut -d '=' -f2)
   docker-compose exec -T mysql mysql --user=root --password="${MYSQL_ROOT_PASSWORD}" --database="${MYSQL_DATABASE}" --execute="SELECT 1"
   ```

6. Stop the projects:

   ```bash
   docker-compose down
   ```

## GitHub Actions

Automated tests and updates are performed using GitHub Actions on every commit to the `main` branch. You can review the configuration files in `.github/workflows`.
