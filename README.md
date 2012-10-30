# .net Decrypt of Node.js SecureStringify

A .net decrypter for data encrypted with node.js serializer.secureStringify

## Background

I was attempting to build out a Proof of Concept showing a single page web app (html, css, javascript, jquery) pulling in data from a RESTful web api. I also wanted to include an OAuth 2.0 hop to make sure only authorized individuals had access to the web apis.

In my attempt to recreate the flow for the Proof of Concept - I searched for a simple OAuth implementation. I found a great implementation by ammmir at https://github.com/ammmir/node-oauth2-provider. This implementation utilizes the underlying node-serializer found at: https://github.com/AF83/node-serializer

Since my web api is in .net, I quickly ran into trouble decrypting and comparing the message digest created in node.js (serializer which relies on crypto which relies on the underlying OpenSsl).  

I searched many stackoverflow questions and many web sites to construct what is contained in this project. This library will parse, decrypt and compare the digest created by secureStringify. The library is not production ready, but should show you how to process the token. Updates are welcome.

## Examples

Look at the test cases to see the processor in use.

## Credits

Compiled from many sources with many coming from http://stackoverflow.com

A great deal of my understanding of the openssl -> .net came from the following web site:
http://deusty.blogspot.com/2009/04/decrypting-openssl-aes-files-in-c.html

## License

BSD
 