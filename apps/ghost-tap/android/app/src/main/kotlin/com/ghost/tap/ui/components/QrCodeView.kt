package com.ghost.tap.ui.components

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Generates a QR code bitmap from the given [content] string using ZXing.
 *
 * @param content  The text to encode into the QR code.
 * @param sizePx   The width/height of the generated bitmap in pixels.
 * @return A monochrome [Bitmap] containing the QR code, or null on failure.
 */
fun generateQrBitmap(content: String, sizePx: Int = 512): Bitmap? {
    return try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val bitMatrix = QRCodeWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            hints
        )
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        bitmap
    } catch (e: Exception) {
        null
    }
}

/**
 * Composable that renders a QR code from the given string content.
 *
 * Uses ZXing core to generate the QR code bitmap and displays it as an
 * [Image] composable. If generation fails, nothing is rendered.
 *
 * @param content  The text to encode.
 * @param size     The display size (dp) of the QR code image.
 * @param modifier Additional [Modifier] applied to the image.
 */
@Composable
fun QrCodeView(
    content: String,
    size: Dp = 256.dp,
    modifier: Modifier = Modifier
) {
    val sizePx = with(androidx.compose.ui.platform.LocalDensity.current) {
        size.roundToPx()
    }

    val bitmap = remember(content, sizePx) {
        generateQrBitmap(content, sizePx)
    }

    bitmap?.let {
        Image(
            bitmap = it.asImageBitmap(),
            contentDescription = "QR Code",
            modifier = modifier.size(size)
        )
    }
}
