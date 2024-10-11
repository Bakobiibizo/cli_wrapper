const pm2 = require('pm2');
const path = require('path');

const pythonScript = path.join(__dirname, 'scripts', "subprocess", "run_cli_wrapper.py");
const rustBinary = path.join(__dirname, 'scripts', 'release', 'cli_wrapper')

pm2.connect((err) => {
    if (err) {
        console.error(err);
        process.exit(2);
    }

    pm2.start({
        script: pythonScript,
        name: 'run_cli_wrapper',
        args: [rustBinary, ...process.argv.slice(2)],
        interpreter: 'python3',
    }, (err, apps) => {
        if (err) {
            console.error(err);
            process.exit(1);
        }

        console.log('CLI wrapper manager started with PM2');
        pm2.disconnect();
    });
});
