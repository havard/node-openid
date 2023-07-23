const fs = require('fs');

fs.writeFileSync('./dist/cjs/package.json', '{"type": "commonjs"}');
fs.writeFileSync('./dist/mjs/package.json', '{"type": "module"}');

const formatFile = (filePath) => {
    const fileContent = fs.readFileSync(filePath)
        .toString()
        .replace(/(from\s+)(["'])(?!.*\.js)(\.?\.\/.*)(["'])/g, '$1$2$3.js$4');

    fs.writeFileSync(filePath, fileContent);
};

const processFiles = (baseFolder) => {
    const fileAndFolderNames = fs.readdirSync(baseFolder);

    fileAndFolderNames.forEach((fileOrFolderName) => {
        if (fileOrFolderName.match(/\..+$/)) {
            // This is a file.
            if (fileOrFolderName.endsWith('.js')) {
                formatFile(`${baseFolder}/${fileOrFolderName}`);
            }
        } else {
            // This is a folder.
            processFiles(`${baseFolder}/${fileOrFolderName}`);
        }
    });
};

// We also have to add explicit `.js` file extensions for our ESM imports.
processFiles('./dist/mjs');