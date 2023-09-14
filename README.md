# docusign

 Prequisites:

 1) You must have node 16 or greater installed on your system
 2) You must have mongodb setup and working on your system

 Installation:

 1) Take checkout of the repository
 2) Run cd docusign/
 3) Run npm install
 4) Run node index.js and project will bootup at 8080 port
 5) Go to http://localhost:8080/


 Setup using Docker:

 Prequisites:

 You should have docker running on your system

 Installation:

 1) Go to project directory
 2) Run the following two commands to get node and mongodb images from docker repository:

  docker pull mohitbhure/docusign:docusign-node

  docker pull mohitbhure/docusign:mongo

 3) Execute the following command to run the container

    docker compose up

This will launch two images and the project will be running at http://localhost:8080/