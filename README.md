# ARCHIVED PROJECT

This project isn't maintained anymore by me. Feel free to fork it!

# Burp Randomizer Extension

You want to scan a particular request of a web app, but there is a
nasty parameter, which needs a different value on each request
(e.g. different name for creating a file)? This extension could be a
solution for your issue. It acts as session handling rule and replaces
a defined token with a random value.

## Usage

Define a session handling rule with a Burp extension action. Choose
randomizer. Don't forget to set an appropriate scope of the session
handling rule.

Send the request to the Repeater/Intruder and put #RANDOM# where
randomization is required. Then send this request to the Scanner,
Intruder or some different tool. The extension now replaces each
occurence of #RANDOM# with a random token and #RANDOMNUM# with random number.

## Configuration

Placeholder, token length and character set can be set in a
configuration section at the beginning of the script code.

WARNING: there seems to be a bug in Burp suite which causes that the
request is truncated at the end when the placeholder length differs
from the token length under certain conditions. Seems related to JSON
requests, but could be something different. Keep lengths equal to stay
safe!
