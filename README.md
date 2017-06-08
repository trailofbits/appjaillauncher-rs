# appjaillauncher-rs
[AppJailLauncher](https://github.com/trailofbits/AppJailLauncher) but in Rust! This is akin to a simple version of **xinetd** for Windows but with sandboxing enabled for the spawned child processes. The sandboxing is accomplished via [AppContainers](goo.gl/5gNlUy).

## Supported Platforms
 * Windows 8 and above
 * Windows Server 2012 and above

### Tested Platforms
 * Windows 10 Professional x64 (build 15063.296)
 
## Creating Challenges
There is an example challenge template in `example/` that can be build using **CMake**.

To build the example challenge:
<pre>
> cd example
> mkdir build
> cd build
> cmake ..
> cmake --build .
</pre>

After building the example challenge, you can use **appjaillauncher-rs** to serve the challenge via the following commands in the root of the repository:

<pre>
> .\target\debug\appjaillauncher-rs.exe run --key .\unittest_support\pub\key2.txt .\example\build\Debug\example_challenge.exe
</pre>

### Questions
#### What does `InitChallenge` do?
The `InitChallenge` will create an timer that will terminate the process after a specified amount of milliseconds and also set `stdout` buffering options to work with network connections. The first part is very important to counter griefing operations directed at your challenges by malicious actors.

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