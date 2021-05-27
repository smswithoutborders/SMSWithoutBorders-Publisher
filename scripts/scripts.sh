#!/bin/bash


# opens port 6969 to all incoming tcp traffic
sudo ufw allow from any to any port 6969 proto tcp

# deny access - NOT TESTED
sudo ufw deny from any to any port 6969 proto tcp
