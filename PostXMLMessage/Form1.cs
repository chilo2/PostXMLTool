using System;
using System.CodeDom;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Text;  // for class Encoding
using System.IO;
using System.Xml;

// for StreamReader

namespace PostXMLMessage
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        void PostMessage()
        {
            string fileName = textBox2.Text;
            string url = textBox1.Text;

            // Check valid fileName set
            if ((!IsEmpty(fileName)) && (!IsEmpty(url)))
            {
                try
                {
                    // Use 100-Continue. This means it is all done in a single connection
                    ServicePointManager.Expect100Continue = true;

                    // Get TLS security protocol selected
                    int nTlsIndex = comboBox2.SelectedIndex;
                    ServicePointManager.SecurityProtocol = GetTlsSecProtocolType(nTlsIndex);

                    // In theory this should never return 0, as technically the drop-down wouldn't allow it.
                    // Added as a belt and brace approach
                    if (ServicePointManager.SecurityProtocol == 0L)
                        throw new NotSupportedException();

                    if ((ServicePointManager.SecurityProtocol == SecurityProtocolType.Tls) || (ServicePointManager.SecurityProtocol == SecurityProtocolType.Tls11))
                    {
                        string tlstext = "";

                        if (ServicePointManager.SecurityProtocol == SecurityProtocolType.Tls)
                            tlstext = "1.0";
                        else
                            tlstext = "1.1";

                        string message = string.Format("WARNING: You have selected TLS v{0} which can be compromised!\r\n\r\n This is not as secure as TLS v1.2", tlstext);
                        MessageBox.Show(message, "Insecure TLS Protocol", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }

                    // Get/Set POST URL
                    var request = (HttpWebRequest) WebRequest.Create(url);

                    // Set HTTP Headers
                    request.Method = "POST";
                    request.ContentType = "text/xml;charset=\"utf-8\"";
                    request.KeepAlive = true;

                    // Use local proxy? (by default 127.0.0.1 and port 8888)
                    if (useProxy.Checked)
                    {
                        // This is the default for Fiddler
                        request.Proxy = new WebProxy("127.0.0.1", 8888);

                        // NOTE. This is WIP, and so the override from the normal 127.0.0.1:8888 might not actually work!
                        // Is there a proxy override set?
                        if (proxyOverride.Checked)
                        {
                            string proxyName = proxyNameTextBox.Text;
                            string proxyPort = proxyPortTextBox.Text;

                            // If no proxy name set, then default back to 127.0.0.1
                            if (IsEmpty(proxyName))
                            {
                                proxyName = "127.0.0.1";
                                string message = string.Format("No 'Override' Proxy IP/Name set. Defaulting to '127.0.0.1'");
                                MessageBox.Show(message, "Unspecified 'Override' Proxy IP/Name", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            }

                            // If no proxy port set, then default back to 8888
                            if (IsEmpty(proxyPort))
                            {
                                proxyPort = "8888";
                                string message = string.Format("No 'Override' Proxy Port set. Defaulting to port '8888'");
                                MessageBox.Show(message, "Unspecified 'Override' Proxy Port", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            }

                            // Use 'override' values set
                            if ((proxyName != "127.0.0.1") && (proxyPort != "8888"))
                                request.Proxy = new WebProxy(proxyNameTextBox.Text, int.Parse(proxyPort));
                        }
                    }
                  
                    // Send "chunked"?
                    if (sendChunked.Checked)
                    {
                        // Set HTTP Header to "chunked"
                        request.SendChunked = true;

                        // Open XML file and get/set total length of file stream into HTTP Header
                        using (Stream fileStream = new FileStream(fileName, FileMode.Open))
                        {
                            request.ContentLength = fileStream.Length;
                            Stream serverStream = request.GetRequestStream();

                            // Get selected index from drop-down (zero based)
                            int nIndex = comboBox1.SelectedIndex;

                            // Get chunk size to determine "chunked" buffer limits
                            int byteSize = GetChunkSize(nIndex);

                            // Create byte array to store relevant "chunked" byte size parts
                            byte[] buffer = new byte[byteSize];
                            while (true)
                            {
                                int bytesRead = fileStream.Read(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                {
                                    serverStream.Write(buffer, 0, bytesRead);
                                }
                                else
                                {
                                    break;
                                }
                            }

                            byteSize = 0;
                            fileStream.Close();
                            serverStream.Close();
                        }
                    }
                    else
                    {
                        using (StreamWriter writer = new StreamWriter(request.GetRequestStream()))
                        {
                            // Write the XML text into the stream
                            writer.WriteLine(this.GetTextFromXMLFile(fileName));
                            writer.Close();
                        }
                    }

                    // Get response from endpoint
                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
                        
                        // Output response to Message Box
                        var CopyToClipBoard = MessageBox.Show(responseString + "\r\n\r\nDo you want to Copy this text to clipboard. If so, press OK, otherwise press Cancel?", "Response Message",
                            MessageBoxButtons.OKCancel, MessageBoxIcon.Information);

                        // If 'OK' pressed, then copy to clipboard
                        if (CopyToClipBoard == DialogResult.OK)
                            Clipboard.SetText(responseString);
                    }
                }

                catch (NotSupportedException ns)
                {
                    string message = string.Format("You have not selected a valid TLS Security Protocol!\r\n{0}", ns.Message);
                    MessageBox.Show(message, "Invalid TLS Security Protocol selected!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                catch (WebException webex)
                {
                    string message = string.Format("Unable to post message \r\n{0}", webex.Message);
                    MessageBox.Show(message, "Error - Unable to Post", MessageBoxButtons.OK, MessageBoxIcon.Error);

                    if (webex.Response != null)
                    {
                        Stream dataStream = webex.Response.GetResponseStream();
                        if (dataStream.CanRead)
                        {
                            StreamReader Reader = new StreamReader(dataStream);
                            message += Reader.ReadToEnd();
                            MessageBox.Show(message);
                        }
                    }
                }

                catch (Exception ex)
                {
                    string message = string.Format("Unable to load {0} \r\n{1}", fileName, ex.Message);
                    MessageBox.Show(message, "Error - Invalid File Path", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                MessageBox.Show("No valid XML File Path or URL has been set!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string GetTextFromXMLFile(string file)
        {
            StreamReader reader = new StreamReader(file);
            string ret = reader.ReadToEnd();
            reader.Close();
            return ret;
        }

        private int GetChunkSize(int nChunkIndex)
        {
            int byteSelected = 0;

            switch (nChunkIndex)
            {
                // 2KB
                case 0:
                byteSelected = 2048;
                break;

                // 4KB (this is the default from combo drop-down)
                case 1:
                byteSelected = 4096;
                break;

                // 8KB
                case 2:
                byteSelected = 8092;
                break;

                // 16KB
                case 3:
                byteSelected = 16384;
                break;

                //32KB
                case 4:
                byteSelected = 32768;
                break;

                // 64KB
                case 5:
                byteSelected = 65536;
                break;

                // 128KB
                default:
                byteSelected = 131072;
                break;
            }

           return byteSelected;
        }

        private SecurityProtocolType GetTlsSecProtocolType(int nSecType)
        {
            ServicePointManager.SecurityProtocol = 0L;      // Initialise to SystemDefault (this is zero).

            if (nSecType == 0L)
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;                // TLS v1.0
            else
                if (nSecType == 1L)
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;          // TLS v1.1
                else
                    if (nSecType == 2L)
                        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;      // TLS v1.2


            // ** NOTE ** - TLS v1.3 can be supported when POST Tool App's Min. Sys Requirements is upgraded to .NET Framework v4.8 (currently Min. is v4.5.2)
            // Not going to worry about this until someone says we need this, and so something to do for the future...

            return ServicePointManager.SecurityProtocol;
        }

        private bool IsEmpty(string text)
        {
            if (!string.IsNullOrEmpty(text))
                return false;

            return true;
        }

        private void sendChunked_CheckedChanged(object sender, EventArgs e)
        {
            comboBox1.Enabled = (sendChunked.CheckState == CheckState.Checked);
        }

        private void useProxy_CheckedChanged(object sender, EventArgs e)
        {
            proxyOverride.Enabled = (useProxy.CheckState == CheckState.Checked);
        }

        private void proxyOverride_CheckedChanged(object sender, EventArgs e)
        {
            labelProxy.Enabled = (proxyOverride.CheckState == CheckState.Checked);
            proxyNameTextBox.Enabled = (proxyOverride.CheckState == CheckState.Checked);
            labelPort.Enabled = (proxyOverride.CheckState == CheckState.Checked);
            proxyPortTextBox.Enabled = (proxyOverride.CheckState == CheckState.Checked);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            PostMessage();
        }
    }
}

