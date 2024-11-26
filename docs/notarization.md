# App Notarization

Since MacOS 10.15, all software distributed with Developer ID (not in the App Store) must be notarized by Apple.
Essentially, the software must be sent to Apple who will scan the software and perform security checks.
They will then issue a "notarization" which can be "stapled" (attached) to the distributed software.
When MacOS executes the software, it will query Apple for whether there is a notarization, or validate the
stapled notarization, and if no notarization is present, refuse the run the software.

## Software Requirements

Apple's notary service requires software to be:

1. Code signed with a "Developer ID" certificate
2. Have the Hardened Runtime capability enabled
3. Have the code signature include a timestamp issued by Apple's timestamp service
4. Link against the MacOS 10.9 or later SDK
5. Have properly formatted XML entitlements
6. Cannot include the `com.apple.security.get-task-allow` entitlement set to `true`.

Using `signapple sign --hardened-runtime` will cover requirements 2, and 3.
Using a "Developer ID" certificate when doing so will cover requirement 1.
It is up to the developer to ensure that the other requirements are met prior to code signing.

## Notarization Submission API Requirements

Notarizing an app requires communicated with Apple's notary service.
This requires having an App Store Connect API key and knowing the "issuer ID" for the API key to generate an API token to communicate with Apple.

To create an App Store Connect API Key:

1. Log in to [App Store Connect](https://appstoreconnect.apple.com/)
2. Choose "Users and Access"
3. Choose "Integrations" in the bar near the top of the page
4. Choose "App Store Connect API" in the left sidebar
5. Click the "+" button next to "Active".
6. In the popup titled "Generate API Key", enter a name, and enter at least "Developer" in "Access". Then click "Generate".
7. Click on the "Download" link to download the private key. Note that you can only download the key once.

To get the issuer ID:

1. Log in to [App Store Connect](https://appstoreconnect.apple.com/)
2. Choose "Users and Access"
3. Choose "Integrations" in the bar near the top of the page
4. Choose "App Store Connect API" in the left sidebar
5. Click the "Copy" link next to the UUID under the heading "Issuer ID".

## Using `signapple notarize`

`signapple notarize` takes 3 arguments: the path to the App Store Connect API Private Key, the Issuer ID UUID string, and the path to the bundle to notarize.

## Notarization Procdure

`signapple` notarizes applications with the process described in https://developer.apple.com/documentation/NotaryAPI/submitting-software-for-notarization-over-the-web

## Stapling

Stapling is the downloading and attachment of the notarization.
Once Apple has accepted the application and issued a notarization, it can be retrieved from their CloudKit API.
Fortunately, this does not require any particular API keys.
The notarization itself is downloaded from the API, decoded, and placed into the file in the bundle `Contents/CodeResources`.
