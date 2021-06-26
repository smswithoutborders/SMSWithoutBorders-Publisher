#!/bin/bash


url="http://localhost:6969"
api_url="http://localhost:9000"
twilio_url="https://smswithoutborders.com:6969/twilio_messages"
twilio_send_url="http://localhost:6969/sms/twilio"
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
	curl -H "Content-Type: application/json" -d "{\"phone_number\":\"673367023\", \"password\":\"asshole101\"}" "${api_url}/users/profiles/login"

elif [ "$d_command" == "--create_user" ] ; then
	echo ">> Creating user..."
	curl -H "Content-Type: application/json" -d "{\"name\":\"sh3rlock\", \"phone_number\":\"673367023\", \"password\":\"asshole101\"}" "${api_url}/users/profiles/register"

elif [ "$d_command" == "--new_session" ] ; then
	echo ">>  new session..."
	curl -H "Content-Type: application/json" -d "{\"auth_key\":\"${phonenumber}\", \"id\":\"${3}\"}" "${url}/sync/sessions"

elif [ "$d_command" == "--sync" ] ; then
	echo ">> syncing user..."
	curl -H "Content-Type: application/json" -d "{\"public_key\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Hh5f/HFiB8P67IUIdhFxE/NryrHKvyQoMvbNq7qzRTj+Fjd1CG9rmjTU6f1UNg49EX7cdz5xWABuml1tmx0+90D84GaMlKGXL6GqJ7YsRrS1Wl+HbDYEnqLThTArZUegHbhyXvhGIlbQknr6mH9MhCkd/hUxLYVh9wvwqtoYVeEsxho929kAwB3fJv81xXP7+nD9IXnB9shLnia44Eo1Xs/3dpLqjw2Mjhz4DUOYMO/lheHAl8V8sJkKQPIbq4k4Hgbml7Xzc0yBu9j7H1FLbtUuud8Q+EHxlhaT9IZ4j4CgtlUW6j0OOQ/vX7NDj+Tr58WCd58GcVnJsmjl0LhlQIDAQAB\"}" "${url}/sync/sessions/${phonenumber}"

elif [ "$d_command" == "--twilio_test" ] ; then
	echo ">> Testing sample twilio request"
	curl -k -X POST -F 'From=000000' -F 'To=11111' -F 'FromCountry=Cameroon' -F 'NumSegments=4' -F 'Body={"phonenumber":"00000", "text":"Hello world Test script"}' "${twilio_url}"

elif [ "$d_command" == "--twilio-send" ] ; then
	echo  ">> Implementing twilio send"
	curl -k -H "Content-Type: application/json" -d "{\"number\":\"${phonenumber}\"}" "${twilio_send_url}" 

elif [ "$d_command" == "--twilio-verify" ] ; then
	echo  ">> Verifying twilio request"
	curl -k -d "{\"session_id\":\"${4}\", \"number\":\"${phonenumber}\", \"code\":\"${3}\"}" "${twilio_send_url}/verification_token" -H "Content-Type: application/json"
fi
