#!/bin/bash


url="http://localhost:6969"
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
fi
