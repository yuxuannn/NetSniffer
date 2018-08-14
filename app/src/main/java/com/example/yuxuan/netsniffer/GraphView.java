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

    private float[] xCoord;
    private float[] yCoord;

    public GraphView(Context context, float[] values, String title, String[] horizontalLabels, String[] verticalLabels, boolean type){
        super(context);

        this.values = values;
        this.title = title;
        this.horizontalLabels = horizontalLabels;
        this.verticalLabels = verticalLabels;
        this.type = type;
        paint = new Paint();

        xCoord = new float[horizontalLabels.length];
        yCoord = new float[horizontalLabels.length];
    }

    @Override
    protected void onDraw(Canvas canvas){

        canvas.drawARGB(10,204,255,255);

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
            //canvas.drawLine(x,height - border, x, border, paint);
            paint.setTextAlign(Align.CENTER);
            if(i == horizontalLabels.length - 1)
                paint.setTextAlign(Align.RIGHT);
            if(i == 0)
                paint.setTextAlign(Align.LEFT);
            paint.setColor(Color.BLACK);
            canvas.drawText(horizontalLabels[i], x, height - 4, paint);
            xCoord[i] = x;
        }

        paint.setTextAlign(Align.CENTER);
        canvas.drawText(title, (graphWidth / 2) + horizontalStart, border - 4, paint);

        calculateYCoord(yCoord, values);

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
                for(int i=0; i<values.length; i++){
                    paint.setColor(Color.RED);
                    canvas.drawLine(xCoord[i], getHeight() - 20, xCoord[i], (getHeight() - yCoord[i]) - 20,  paint); // !!
                    //paint.setColor(Color.BLACK);
                    //canvas.drawText(Float.toString(values[i]),xCoord[i] + 5,getHeight() - 20, paint);
                    paint.setColor(Color.LTGRAY);
                    if(i>0)
                        canvas.drawLine(xCoord[i-1],getHeight()-yCoord[i-1], xCoord[i],(getHeight() - yCoord[i]) - 20, paint);
                }

                float avg = getAvg();
                paint.setColor(Color.GREEN);
                canvas.drawLine(40, getHeight() - avg, width, (getHeight() - avg) - 20, paint); // !!
                paint.setColor(Color.BLACK);
                canvas.drawText("Avg.",80,getHeight() - avg - 5, paint);
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

    private float getAvg(){
        float average = 0;
        for(int i=0; i<yCoord.length; i++)
            average += yCoord[i];
        average /= yCoord.length;
        return average;
    }

    private float[] calculateYCoord(float[] yCoord, float[] values){
        for(int i=0; i<values.length; i++)
            yCoord[i] = (values[i] / getMax()) * getHeight();                // change 2.0f to variable max
        return yCoord;
    }
}
