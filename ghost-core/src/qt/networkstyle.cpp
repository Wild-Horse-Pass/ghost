// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkstyle.h>

#include <qt/guiconstants.h>

#include <tinyformat.h>
#include <util/chaintype.h>

#include <QApplication>

static const struct {
    const ChainType networkId;
    const char *appName;
    const int iconColorHueShift;
    const int iconColorSaturationReduction;
} network_styles[] = {
    // Ghost branding: Keep orange icon consistent across all networks
    // Network is indicated by [testnet]/[regtest] in title bar instead
    {ChainType::MAIN, QAPP_APP_NAME_DEFAULT, 0, 0},
    {ChainType::TESTNET, QAPP_APP_NAME_TESTNET, 0, 0},
    {ChainType::TESTNET4, QAPP_APP_NAME_TESTNET4, 0, 0},
    {ChainType::SIGNET, QAPP_APP_NAME_SIGNET, 0, 0},
    {ChainType::REGTEST, QAPP_APP_NAME_REGTEST, 0, 0},
};

// titleAddText needs to be const char* for tr()
NetworkStyle::NetworkStyle(const QString &_appName, const int iconColorHueShift, const int iconColorSaturationReduction, const char *_titleAddText):
    appName(_appName),
    titleAddText(qApp->translate("SplashScreen", _titleAddText))
{
    // load pixmap
    QPixmap pixmap(":/icons/ghost");

    if(iconColorHueShift != 0 && iconColorSaturationReduction != 0)
    {
        // generate QImage from QPixmap
        QImage img = pixmap.toImage();

        int h,s,l,a;

        // traverse though lines
        for(int y=0;y<img.height();y++)
        {
            QRgb *scL = reinterpret_cast< QRgb *>( img.scanLine( y ) );

            // loop through pixels
            for(int x=0;x<img.width();x++)
            {
                // preserve alpha because QColor::getHsl doesn't return the alpha value
                a = qAlpha(scL[x]);
                QColor col(scL[x]);

                // get hue value
                col.getHsl(&h,&s,&l);

                // rotate color on RGB color circle
                // 70° should end up with the typical "testnet" green
                h+=iconColorHueShift;

                // change saturation value
                if(s>iconColorSaturationReduction)
                {
                    s -= iconColorSaturationReduction;
                }
                col.setHsl(h,s,l,a);

                // set the pixel
                scL[x] = col.rgba();
            }
        }

        //convert back to QPixmap
        pixmap.convertFromImage(img);
    }

    appIcon             = QIcon(pixmap);

    // Use ghost icon with orange circle for window/tray icon
    // Add multiple sizes for better compatibility with X11/WSL
    QPixmap windowIconPixmap(":/icons/ghost_icon");
    trayAndWindowIcon = QIcon();
    // Add multiple sizes for X11/WSL compatibility
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(16,16), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(24,24), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(32,32), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(48,48), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(64,64), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(128,128), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    trayAndWindowIcon.addPixmap(windowIconPixmap.scaled(QSize(256,256), Qt::KeepAspectRatio, Qt::SmoothTransformation));
}

const NetworkStyle* NetworkStyle::instantiate(const ChainType networkId)
{
    std::string titleAddText = networkId == ChainType::MAIN ? "" : strprintf("[%s]", ChainTypeToString(networkId));
    for (const auto& network_style : network_styles) {
        if (networkId == network_style.networkId) {
            return new NetworkStyle(
                    network_style.appName,
                    network_style.iconColorHueShift,
                    network_style.iconColorSaturationReduction,
                    titleAddText.c_str());
        }
    }
    return nullptr;
}
