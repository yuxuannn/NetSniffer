package com.example.yuxuan.netsniffer;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Paint.Align;
import android.view.View;

public class GraphView extends View {

    public final boolean BAR = true;
    public final boolean LINE = false;

    private Paint paint;
    private float[] values;
    private String[] horizontalLabels;
    private String[] verticalLabels;
    private String title;
    private boolean type;

    public GraphView(Context context, float[] values, String title, String[] horizontalLabels, String[] verticalLabels, boolean type){
        super(context);

        this.values = values;
        this.title = title;
        this.horizontalLabels = horizontalLabels;
        this.verticalLabels = verticalLabels;
        this.type = type;
        paint = new Paint();
    }

    @Override
    protected void onDraw(Canvas canvas){
        float border = 20;
        float horizontalStart = border * 2;
        float height = getHeight();
        float width = getWidth() - 1;
        float max = getMax();
        float min = getMin();
        float diff = max - min;
        float graphHeight = height - (2 * border);
        float graphWidth = width - (2 * border);

        paint.setTextAlign(Align.LEFT);

        int noVert = verticalLabels.length - 1;
        for(int i=0; i<verticalLabels.length; i++){
            paint.setColor(Color.DKGRAY);
            float y = ((graphHeight / noVert) * i) + border;
            canvas.drawLine(horizontalStart, y, width, y, paint);
            paint.setColor(Color.BLACK);
            canvas.drawText(verticalLabels[i],0, y,paint);
        }

        int noHoriz = horizontalLabels.length - 1;
        for(int i=0; i<horizontalLabels.length; i++){
            paint.setColor(Color.DKGRAY);
            float x = ((graphWidth / noHoriz) * i) + horizontalStart;
            canvas.drawLine(x,height - border, x, border, paint);
            paint.setTextAlign(Align.CENTER);
            if(i == horizontalLabels.length - 1)
                paint.setTextAlign(Align.RIGHT);
            if(i == 0)
                paint.setTextAlign(Align.LEFT);
            paint.setColor(Color.BLACK);
            canvas.drawText(horizontalLabels[i], x, height - 4, paint);
        }

        paint.setTextAlign(Align.CENTER);
        canvas.drawText(title, (graphWidth / 2) + horizontalStart, border - 4, paint);

        if(max != min){
            paint.setColor(Color.LTGRAY);
            if(type == BAR){
                float datalength = values.length;
                float colwidth = (width - (2 * border)) / datalength;
                for(int i=0; i<values.length; i++) {
                    float val = values[i] - min;
                    float rat = val / diff;
                    float h = graphHeight * rat;
                    canvas.drawRect((i * colwidth) + horizontalStart, (border - h) + graphHeight, ((i * colwidth) + horizontalStart) + (colwidth - 1), height - (border - 1), paint);
                }
            } else {
                float datalength = values.length;
                float colwidth = (width - (2 * border)) / datalength;
                float halfcol = colwidth / 2;
                float lasth = 0;
                for(int i=0; i<values.length; i++){
                    float val = values[i] - min;
                    float rat = val / diff;
                    float h = graphHeight * rat;
                    if(i > 0)
                        canvas.drawLine(((i - 1) * colwidth) + (horizontalStart + 1) + halfcol, (border - lasth) + graphHeight, (i * colwidth) + (horizontalStart + 1) + halfcol, (border - h) + graphHeight, paint);
                    lasth = h;
                }
            }
        }
    }

    private float getMax(){
        float largest = Integer.MIN_VALUE;
        for(int i=0; i<values.length; i++)
            if(values[i] > largest)
                largest = values[i];
        return largest;
    }

    private float getMin(){
        float smallest = Integer.MAX_VALUE;
        for(int i=0; i<values.length; i++)
            if(values[i] < smallest)
                smallest = values[i];
        return smallest;
    }
}
