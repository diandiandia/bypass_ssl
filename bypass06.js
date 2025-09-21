function hook_java() {
  if (Java.available) {
    Java.perform(function () {
      // 动态获取包名
      var pkgName = Java.use("android.app.ActivityThread")
        .currentApplication()
        .getApplicationContext()
        .getPackageName();
      console.log("[+] Package name: " + pkgName);
      var outputDir = "/data/data/" + pkgName + "/";

      // 生成随机文件名
      function uuid(len) {
        var chars =
          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".split(
            ""
          );
        var uuid = [];
        for (var i = 0; i < len; i++) {
          uuid.push(chars[Math.floor(Math.random() * chars.length)]);
        }
        return uuid.join("");
      }

      // 将证书和私钥保存为 PKCS12
      function storeP12(privateKey, certificate, p12Path, p12Password) {
        try {
          var X509Certificate = Java.use("java.security.cert.X509Certificate");
          var cert = Java.cast(certificate, X509Certificate);
          var chain = Java.array("java.security.cert.X509Certificate", [cert]);
          var ks = Java.use("java.security.KeyStore").getInstance("PKCS12");
          ks.load(null, null);
          ks.setKeyEntry(
            "client",
            privateKey,
            p12Password.toCharArray(),
            chain
          );
          var out = Java.use("java.io.FileOutputStream").$new(p12Path);
          ks.store(out, p12Password.toCharArray());
          out.close();
          console.log(
            "[+] Saved PKCS12 to " + p12Path + ", password: " + p12Password
          );
        } catch (e) {
          console.log("[-] Error saving PKCS12: " + e);
        }
      }

      // Hook PrivateKeyEntry.getPrivateKey
      Java.use(
        "java.security.KeyStore$PrivateKeyEntry"
      ).getPrivateKey.implementation = function () {
        var privateKey = this.getPrivateKey();
        var certificate = this.getCertificate();
        var p12Path = outputDir + "client_cert_" + uuid(8) + ".p12";
        var p12Password = "r0ysue"; // 默认密码
        storeP12(privateKey, certificate, p12Path, p12Password);
        console.log("[+] Dumped client certificate and key to " + p12Path);
        return privateKey;
      };

      // Hook PrivateKeyEntry.getCertificateChain
      Java.use(
        "java.security.KeyStore$PrivateKeyEntry"
      ).getCertificateChain.implementation = function () {
        var certChain = this.getCertificateChain();
        var privateKey = this.getPrivateKey();
        var certificate = this.getCertificate();
        var p12Path = outputDir + "client_chain_" + uuid(8) + ".p12";
        var p12Password = "r0ysue"; // 默认密码
        storeP12(privateKey, certificate, p12Path, p12Password);
        console.log("[+] Dumped certificate chain to " + p12Path);
        return certChain;
      };

      //SSLpinning helper 帮助定位证书绑定的关键代码a
      Java.use("java.io.File").$init.overload(
        "java.io.File",
        "java.lang.String"
      ).implementation = function (file, cert) {
        var result = this.$init(file, cert);
        var stack = Java.use("android.util.Log").getStackTraceString(
          Java.use("java.lang.Throwable").$new()
        );
        if (
          file.getPath().indexOf("cacert") >= 0 &&
          stack.indexOf("X509TrustManagerExtensions.checkServerTrusted") >= 0
        ) {
          console.log("[+] SSLpinning position locator => " + file.getPath() + " " + cert);
        }
        return result;
      };

      Java.use("java.net.SocketOutputStream").socketWrite0.overload(
        "java.io.FileDescriptor",
        "[B",
        "int",
        "int"
      ).implementation = function (fd, bytearry, offset, byteCount) {
        var result = this.socketWrite0(fd, bytearry, offset, byteCount);
        // 打印发送的数据
        return result;
      };
      Java.use("java.net.SocketInputStream").socketRead0.overload(
        "java.io.FileDescriptor",
        "[B",
        "int",
        "int",
        "int"
      ).implementation = function (fd, bytearry, offset, byteCount, timeout) {
        var result = this.socketRead0(fd, bytearry, offset, byteCount, timeout);
        // 打印读取到的数据
        return result;
      };

      if (parseFloat(Java.androidVersion) > 8) {
        Java.use(
          "com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream"
        ).write.overload("[B", "int", "int").implementation = function (
          bytearry,
          int1,
          int2
        ) {
          var result = this.write(bytearry, int1, int2);
          SSLstackwrite = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Throwable").$new())
            .toString();
          return result;
        };
        Java.use(
          "com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream"
        ).read.overload("[B", "int", "int").implementation = function (
          bytearry,
          int1,
          int2
        ) {
          var result = this.read(bytearry, int1, int2);
          SSLstackread = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Throwable").$new())
            .toString();
          return result;
        };
      } else {
        Java.use(
          "com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream"
        ).write.overload("[B", "int", "int").implementation = function (
          bytearry,
          int1,
          int2
        ) {
          var result = this.write(bytearry, int1, int2);
          SSLstackwrite = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Throwable").$new())
            .toString();
          return result;
        };
        Java.use(
          "com.android.org.conscrypt.OpenSSLSocketImpl$SSLInputStream"
        ).read.overload("[B", "int", "int").implementation = function (
          bytearry,
          int1,
          int2
        ) {
          var result = this.read(bytearry, int1, int2);
          SSLstackread = Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Throwable").$new())
            .toString();
          return result;
        };
      }
    });
  }
}

setTimeout(hook_java, 0);
