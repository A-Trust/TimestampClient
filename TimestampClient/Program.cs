using Org.BouncyCastle.Tsp;
using TimestampGithubExample;

Console.WriteLine("Timestamp RFC 3161 will be retrieved:");

#region appsettings
string username = "test";
string password = "test";
string tsServerUrl = "https://test1.a-trust.at/";

if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
{
    Console.WriteLine("Username and password have to be set!");
}
if (string.IsNullOrEmpty(tsServerUrl))
{
    Console.WriteLine("No URL of the Timestamp-Server was set!");
}

#endregion

TimeStampHelper tsHelper = new TimeStampHelper(username, password, tsServerUrl);

string data = "This string will be timestamped";

#region generate TimeStampRequest & send it

TimeStampRequest tsRequest = tsHelper.generateRequest(data);

TimeStampResponse tsResponse = tsHelper.sendRequest(tsRequest);

if (tsResponse == null)
{
    Console.WriteLine("The HTTP Request failed.");
    return;
}

#endregion

// The certificate against which the TimestampToken will be validated in the validate method.
byte[] tsTestCertificate = File.ReadAllBytes("../../../signer.cer");

tsHelper.Validate(tsResponse, tsRequest, tsTestCertificate);
