This sample plugin demonstrates how to perform gateway authentication via a custom plugin for SPS-initiated sessions
while using SPP as the credential store.

The example code in `plugin/plugin_bare.py` demonstrates how to read the `identity_provider` property from the plugin
configuration. It then prompts the user to enter a user name and password, which can be used to authenticate the user
with a third-party authentication provider.
The `identity_provider` value must be set in the session cookie to pass the information to SPP. It should match the
identity provider name configured in SPP when it was added.
