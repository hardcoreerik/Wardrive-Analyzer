package com.wardrive.analyzer.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.wardrive.analyzer.android.R

private val NeonDark = darkColorScheme(
    primary = Color(0xFF00F5D4),
    onPrimary = Color(0xFF001414),
    secondary = Color(0xFF00C8FF),
    onSecondary = Color(0xFF00131A),
    background = Color(0xFF090312),
    onBackground = Color(0xFFE6FFFA),
    surface = Color(0xFF12051E),
    onSurface = Color(0xFFE6FFFA),
    surfaceVariant = Color(0xFF1B0A2A),
    outline = Color(0xFF00A3C4)
)

private val PixelFont = FontFamily(Font(R.font.press_start_2p_regular))

private val NeonTypography = Typography(
    headlineMedium = TextStyle(
        fontFamily = PixelFont,
        fontSize = 30.sp,
        fontWeight = FontWeight.ExtraBold,
        letterSpacing = 0.8.sp,
        lineHeight = 34.sp
    ),
    titleMedium = TextStyle(
        fontFamily = PixelFont,
        fontSize = 14.sp,
        fontWeight = FontWeight.SemiBold,
        lineHeight = 18.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = PixelFont,
        fontSize = 13.sp,
        lineHeight = 18.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = PixelFont,
        fontSize = 12.sp,
        lineHeight = 16.sp
    ),
    bodySmall = TextStyle(
        fontFamily = PixelFont,
        fontSize = 10.sp,
        lineHeight = 14.sp
    ),
    labelLarge = TextStyle(
        fontFamily = PixelFont,
        fontSize = 11.sp,
        lineHeight = 14.sp
    )
)

@Composable
fun WardriveTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = NeonDark,
        typography = NeonTypography,
        content = content
    )
}
