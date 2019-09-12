# react-native-ecp

## Getting started

`$ npm install react-native-ecp --save`

### Mostly automatic installation

`$ react-native link react-native-ecp`

### Manual installation


#### iOS

1. In XCode, in the project navigator, right click `Libraries` ➜ `Add Files to [your project's name]`
2. Go to `node_modules` ➜ `react-native-ecp` and add `Ecp.xcodeproj`
3. In XCode, in the project navigator, select your project. Add `libEcp.a` to your project's `Build Phases` ➜ `Link Binary With Libraries`
4. Run your project (`Cmd+R`)<

#### Android

1. Open up `android/app/src/main/java/[...]/MainApplication.java`
  - Add `import com.reactlibrary.EcpPackage;` to the imports at the top of the file
  - Add `new EcpPackage()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-ecp'
  	project(':react-native-ecp').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-ecp/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-ecp')
  	```


## Usage
```javascript
import Ecp from 'react-native-ecp';

// TODO: What to do with the module?
Ecp;
```
# react-native-ecp
