# shellcode-injector
While researching remote code execution, I stumbled across information that identified the massive security hole within one of Microsoft's Windows API functions, 'SetWindowsHookEx'. As documented, this function installs an application-defined hook procedure into a hook chain. At first glance, this is of no significance. However, as per analysis by [Waryas](https://github.com/waryas/), a series of tests will confirm that the hook procedure does not need to belong to the module passed to the function. This has serious implications and enables remote procedure calls from any process via thread hijacking, as showcased by this project.
# Note
In the spirit of stealth, I am using direct syscalls rather than WinAPI / Native API calls to stay under the radar of inline hooks.
# Planned
* Other thread hijacking methods
* Using this method (in addition to the methods I add) for DLL injections
