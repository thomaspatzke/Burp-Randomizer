# Burp Randomizer Extension
# Copyright 2014 Thomas Skora <thomas@skora.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import (IBurpExtender, ISessionHandlingAction)
import re
import string
import random

### Configuration ###
# Character set of generated tokens
tokenCharset = string.ascii_letters + string.digits
# String which is replaced with random token
placeholder = "#RANDOM#"
# Length of generated token. WARNING: length of token must equal length of placeholder due to a bug in Burp 1.5.21 which cuts off requests under certain conditions.
tokenLength = len(placeholder)
#####################


class BurpExtender(IBurpExtender, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Randomizer")
        self.callbacks.registerSessionHandlingAction(self)
        self.out = callbacks.getStdout()
        self.placeholder = re.compile(placeholder)
        random.seed()

    ### ISessionHandlingAction ###
    def getActionName(self):
        return "Randomizer"
    
    def performAction(self, currentRequest, macroItems):
        request = self.helpers.bytesToString(currentRequest.getRequest())
        randomToken = "".join([random.choice(tokenCharset) for i in range(tokenLength)])
        result = self.helpers.stringToBytes(self.placeholder.sub(randomToken, request))
        currentRequest.setRequest(result)
