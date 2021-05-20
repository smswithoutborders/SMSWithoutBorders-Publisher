#!/bin/bash


url="http://localhost:6969"
api_url="http://localhost:9000"
d_command=$1
phonenumber=$2

if [ "$d_command" == "--send" ] ; then
	if [ "$phonenumber" == "" ] ; then
		echo "Phone number required but not provided.."
	else
		echo ">> Sending..."
		# date=$(date)
		# platform:protocol:<body>
		curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"gmail:send:New time found-$(date +%s):afkanerd@gmail.com:$(date)\nBest,\nWisdom\",\"phonenumber\":\"${phonenumber}\"}" "${url}/messages"
	fi

elif [ "$d_command" == "--received" ] ; then
	echo ">> Fetching received..."
	curl -X GET "${url}/messages"

elif [ "$d_command" == "--get_auth" ] ; then
	echo ">> Fetching auth key..."
	curl -H "Content-Type: application/json" -d "{\"phone_number\":\"123456\", \"password\":\"1234567890123456\"}" "${api_url}/users/profiles/login"
elif [ "$d_command" == "--create_user" ] ; then
	echo ">> Creating user..."
	curl -H "Content-Type: application/json" -d "{\"phone_number\":\"123456\", \"password\":\"1234567890123456\"}" "${api_url}/users/profiles/register"
elif [ "$d_command" == "--new_session" ] ; then
	echo ">> Creating user..."
	curl -H "Content-Type: application/json" -d "{\"auth_key\":\"123456\", \"password\":\"1234567890123456\"}" "${api_url}/users/profiles/register"
fi
