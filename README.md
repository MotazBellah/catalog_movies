## The Movie website:

This site provides a list of items within a variety of movie genres as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own movies.
This website is fully responsive as well, so user can access it from any device with small screen or large one. 

## Code style:

This project is written in python 2 and follow PEP-8 Guidelines.

## Getting Started:

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

## Prerequisites:

### Installing the Vagrant VM:
#### Git

If you don't already have Git installed, download Git from git-scm.com. Install the version for your operating system.
On Windows, Git will provide you with a Unix-style terminal and shell (Git Bash). (On Mac or Linux systems you can use the regular terminal program.)
You will need Git to install the configuration for the VM.

#### VirtualBox

VirtualBox is the software that actually runs the VM. You can download it from virtualbox.org. Install the platform package for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it.

Ubuntu 14.04 Note: If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center, not the virtualbox.org web site. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

#### Vagrant

Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. You can download it from vagrantup.com. Install the version for your operating system.

Windows Note: The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

## Run:
 Open the terminal
 Windows: Use the Git Bash program (installed with Git) to get a Unix-style terminal.

Other systems: Use your favorite terminal program.

### Fork the repo

Log into your personal Github account, and fork the catalog_item repo so that you have a personal repo you can push to for backup.

### Clone the remote to your local machine

Download the project to your local machine

### Run the virtual machine

Using the terminal, change directory to oauth using the command cd <Project directory>, then type vagrant up to launch your virtual machine.

### Running the Movie app

Once it is up and running, type vagrant ssh. This will log your terminal into the virtual machine, and you'll get a Linux shell prompt. When you want to log out, type exit at the shell prompt. To turn the virtual machine off (without deleting anything), type vagrant halt. If you do this, you'll need to run vagrant up again before you can log into it.

Now that you have Vagrant up and running type vagrant ssh to log into your VM. Change directory to the /vagrant directory by typing cd /vagrant. This will take you to the shared folder between your virtual machine and host machine.

Type ls to ensure that you are inside the directory that contains app.py, database_setup.py, and two directories named 'templates' and 'static'

Now type python database_setup.py to initialize the database.


Type python app.py to run the Flask web server. In your browser visit http://localhost:8000 to view the movie app. You should be able to view, add, edit, and delete the movies.
