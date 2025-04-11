import hashlib
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JTextField, BoxLayout
from java.io import PrintWriter
from java.awt import Component
import json
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Captcha Parameter Extractor")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stdout.println("[*] Captcha Parameter Extractor Loaded")

        # UI setup - vertical layout
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        # Labels + fields for difficulty, salt, hash, captcha-solution, and session-token
        self._difficultyLabel = JLabel("difficulty:")
        self._difficultyField = JTextField(40)
        self._difficultyField.setEditable(False)

        self._saltLabel = JLabel("salt:")
        self._saltField = JTextField(40)
        self._saltField.setEditable(False)

        self._hashLabel = JLabel("hash:")
        self._hashField = JTextField(40)
        self._hashField.setEditable(False)

        self._captchaLabel = JLabel("captcha-solution:")
        self._captchaField = JTextField(40)
        self._captchaField.setEditable(False)

        self._sessionTokenLabel = JLabel("session-token:")
        self._sessionTokenField = JTextField(40)
        self._sessionTokenField.setEditable(False)

        # Add components to panel
        for label, field in [
            (self._difficultyLabel, self._difficultyField),
            (self._saltLabel, self._saltField),
            (self._hashLabel, self._hashField),
            (self._captchaLabel, self._captchaField),
            (self._sessionTokenLabel, self._sessionTokenField)
        ]:
            label.setAlignmentX(Component.LEFT_ALIGNMENT)
            field.setAlignmentX(Component.LEFT_ALIGNMENT)
            self._panel.add(label)
            self._panel.add(field)

        # Register as tab and HTTP listener
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def getTabCaption(self):
        return "Captcha Solver"

    def getUiComponent(self):
        return self._panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_REPEATER and not messageIsRequest:
            try:
                # Extract the response body
                response_bytes = messageInfo.getResponse()
                response_info = self._helpers.analyzeResponse(response_bytes)
                body_offset = response_info.getBodyOffset()
                body = response_bytes[body_offset:]
                body_str = body.tostring()

                # Extract the Set-Cookie header for session-token
                headers = response_info.getHeaders()
                session_token = self.extract_session_token(headers)

                # Try parsing the JSON body
                json_obj = json.loads(body_str)

                difficulty = int(json_obj.get("difficulty", "Not found"))
                salt = json_obj.get("salt", "Not found")
                hash_val = json_obj.get("hash", "Not found")

                # Update fields with extracted values
                self._difficultyField.setText(str(difficulty))
                self._saltField.setText(salt)
                self._hashField.setText(hash_val)

                # Calculate the captcha solution using the logic
                captcha_solution = self.solve_captcha(difficulty, salt, hash_val)

                # Update the captcha-solution field
                if captcha_solution is not None:
                    self._captchaField.setText(str(captcha_solution))
                else:
                    self._captchaField.setText("Not found")

                # Update the session-token field
                if session_token:
                    self._sessionTokenField.setText(session_token)
                else:
                    self._sessionTokenField.setText("Not found")

            except Exception as e:
                self.stdout.println("[!] Error parsing response or updating UI: " + str(e))

    def extract_session_token(self, headers):
        """
        Extracts the session token from the Set-Cookie header.
        """
        for header in headers:
            if header.lower().startswith("set-cookie:"):
                # Look for __Secure-next-auth.session-token cookie in the header
                match = re.search(r"__Secure-next-auth\.session-token=([^;]+)", header)
                if match:
                    return match.group(1)  # Return the session token value
        return None

    def solve_captcha(self, difficulty, salt, hash_value):
        """
        Solves the captcha by finding the value of r that satisfies the hash condition.
        Uses SHA512 to hash the salt + r in hexadecimal format.
        """
        r = 0
        while r < difficulty:
            r_hex = format(r, 'x')  # hex without 0x
            input_str = salt + r_hex
            hashed = hashlib.sha512(input_str.encode('utf-8')).hexdigest()
            if hashed == hash_value:
                return r
            r += 1
        return None
