# appjaillauncher-rs
[AppJailLauncher](https://github.com/trailofbits/AppJailLauncher) but in Rust! This is akin to a simple version of **xinetd** for Windows but with sandboxing enabled for the spawned child processes. The sandboxing is accomplished via [AppContainers](https://goo.gl/5gNlUy).

## Supported Platforms
 * Windows 8 and above
 * Windows Server 2012 and above

### Tested Platforms
 * Windows 10 Professional x64 (build 14393.1198)
 * Windows 10 Professional x64 (build 15063.296)
 
## Creating Challenges
There is an example challenge template in `example/` that can be built using **CMake**.

To build the example challenge:
<pre>
> cd example
> mkdir build
> cd build
> cmake ..
> cmake --build .
</pre>

After building the example challenge, you can use **appjaillauncher-rs** to serve the challenge via the following command in the root of the repository:

<pre>
> .\target\debug\appjaillauncher-rs.exe run --key .\unittest_support\pub\key2.txt .\example\build\Debug\example_challenge.exe
</pre>

## Frequently Asked Questions
#### In the example challenge, what does `InitChallenge` do?
The `InitChallenge` function will create an timer that will terminate the process after a specified amount of milliseconds and  set `stdout` buffering options to work better with network sockets. The first part is essential for countering griefing operations directed at your challenges by malicious actors.

#### I think something is broke, is there a way to get more logging?
**appjaillauncher-rs** uses **env_logger** for logging. This means you can get more debug logging by setting the `RUST_LOG` environment variable to `debug`. For example, in PowerShell, the following command would be sufficient: 
<pre>
> $env:RUST_LOG="debug"
</pre>

#### How do I target x86 Windows from x64 Windows with Rust?
`rustup` should be part of the default Rust install. First, use `rustup` to add the new x86 target:
<pre>
> rustup target add i686-pc-windows-msvc
</pre>
After installation, add `--target=i686-pc-windows-msvc` to the `cargo build`, `cargo test` commands to build for x86.

#### I have a complex ACL setup for my key, why won't things work?
Our ACL implementation is simple and should work on _most_ configurations. However, it is entirely possible that for complex ACL setups, this will not work as intended. If you run into any issues, file an issue.

#### `cargo build` is complaining that `msvc targets depend on msvc linker but "link.exe" was not found`
You need to at least install [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe).

## Development
First, follow the instructions [here](https://www.rust-lang.org/en-US/install.html) and install Rust.

After installing Rust, grab the latest **appjaillauncher-rs** source code via the following:
<pre>
> git clone https://github.com/trailofbits/appjaillauncher-rs
> cd appjaillauncher-rs
</pre>

To build **appjaillauncher-rs**:
<pre>
> cargo build
</pre>

To run the unit tests:
<pre>
> cargo test
</pre>

## Authors
 * [Andy Ying](https://github.com/yying)
