package com.ghost.tap.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val GhostPurple = Color(0xFF6B4EE6)
private val GhostPurpleLight = Color(0xFF9D8AEF)
private val GhostPurpleDark = Color(0xFF4A35A3)

private val DarkColorScheme = darkColorScheme(
    primary = GhostPurpleLight,
    onPrimary = Color.Black,
    primaryContainer = GhostPurpleDark,
    onPrimaryContainer = Color.White,
    secondary = GhostPurpleLight,
    tertiary = GhostPurpleLight,
    background = Color(0xFF121212),
    surface = Color(0xFF1E1E1E),
)

private val LightColorScheme = lightColorScheme(
    primary = GhostPurple,
    onPrimary = Color.White,
    primaryContainer = GhostPurpleLight,
    onPrimaryContainer = Color.Black,
    secondary = GhostPurple,
    tertiary = GhostPurple,
    background = Color(0xFFFFFBFE),
    surface = Color(0xFFFFFBFE),
)

@Composable
fun GhostTapTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
