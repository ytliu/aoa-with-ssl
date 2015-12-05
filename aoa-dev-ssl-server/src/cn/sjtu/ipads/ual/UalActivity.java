package cn.sjtu.ipads.ual;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class UalActivity extends Activity
{
  private static String TAG = "UalActivity";

  /** Called when the activity is first created. */
  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.main);

    Log.v(TAG, "onCreate()");
	/*Intent i = (new Intent(this, UalTraActivity.class));
    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
        | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    startActivity(i);
    
    finish();*/
  }
}
