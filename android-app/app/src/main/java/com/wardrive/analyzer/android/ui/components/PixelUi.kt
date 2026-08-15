package com.wardrive.analyzer.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

val PixelCyan = Color(0xFF12C8FF)
val PixelBlue = Color(0xFF1D66FF)
val PixelGreen = Color(0xFF48F772)
val PixelRed = Color(0xFFFF4A59)
val PixelPurple = Color(0xFF9066FF)
val PixelPanelBg = Color(0xFF081326)

@Composable
fun PixelPanel(
    title: String? = null,
    modifier: Modifier = Modifier,
    accent: Color = PixelCyan,
    content: @Composable () -> Unit
) {
    Column(
        modifier = modifier
            .border(BorderStroke(2.dp, accent), RoundedCornerShape(2.dp))
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(PixelPanelBg.copy(alpha = 0.98f), Color(0xFF04101E))
                ),
                shape = RoundedCornerShape(2.dp)
            )
            .padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        if (!title.isNullOrBlank()) {
            Text(
                text = title.uppercase(),
                color = accent,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                letterSpacing = 1.1.sp
            )
        }
        content()
    }
}

@Composable
fun PixelStatCard(
    title: String,
    value: String,
    subtitle: String,
    accent: Color,
    modifier: Modifier = Modifier
) {
    PixelPanel(title = title, modifier = modifier, accent = accent) {
        Text(value, color = accent, fontWeight = FontWeight.ExtraBold, fontSize = 20.sp)
        Text(subtitle, color = Color(0xFFA9BCD5), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun PixelChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val border = if (selected) PixelCyan else Color(0xFF2D4260)
    val bg = if (selected) Color(0xFF0E2942) else Color(0xFF0A1628)
    androidx.compose.material3.TextButton(
        onClick = onClick,
        modifier = modifier
            .border(2.dp, border, RoundedCornerShape(1.dp))
            .background(bg)
    ) {
        Text(text, color = if (selected) PixelCyan else Color(0xFF97A9C6), fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun PixelLegendDot(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(color, RoundedCornerShape(1.dp))
        )
        Text(label, color = Color(0xFFBED2EC), style = MaterialTheme.typography.bodySmall)
    }
}
